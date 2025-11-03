defmodule Rsolv.AST.TestIntegrator do
  @moduledoc """
  Integrates security tests into existing test files using AST manipulation.

  Parses target test file, finds appropriate insertion point, inserts new test,
  and serializes back to code. Falls back to simple append if AST fails.

  Currently supports:
  - JavaScript/TypeScript with Jest, Vitest, and Mocha frameworks

  ## Examples

      iex> original_code = \"\"\"
      ...> describe('UsersController', () => {
      ...>   it('creates user', () => {
      ...>     expect(User.count()).toBe(1);
      ...>   });
      ...> });
      ...> \"\"\"
      iex> test_suite = %{
      ...>   "redTests" => [%{
      ...>     "testName" => "rejects SQL injection",
      ...>     "testCode" => "expect(() => search_users(payload)).toThrow()",
      ...>     "attackVector" => "'; DROP TABLE users;--"
      ...>   }]
      ...> }
      iex> {:ok, integrated, _point, method} = Rsolv.AST.TestIntegrator.generate_integration(
      ...>   original_code, test_suite, "javascript", "vitest"
      ...> )
      iex> String.contains?(integrated, "rejects SQL injection")
      true
      iex> method
      "ast"

  """

  alias Rsolv.AST.SessionManager
  alias Rsolv.AST.ParserRegistry
  alias Rsolv.AST.Languages
  alias Rsolv.AST.Formatters
  alias Rsolv.AST.Validators
  require Logger

  @supported_frameworks ~w(vitest jest mocha)
  @default_indent 2

  @doc """
  Simple API for inserting a single test into existing test code.

  This is a backward-compatible wrapper around `generate_integration/4` for tests
  that just want to insert a single test string without the full test_suite structure.

  ## Parameters

  - `target_code`: The existing test file content as a string
  - `test_code`: The test code to insert as a string
  - `language`: Language atom (`:javascript`, `:ruby`, `:python`, etc.)

  ## Examples

      iex> insert_test("describe('Foo', () => {});", "it('works', () => {})", :javascript)
      {:ok, "describe('Foo', () => {\\n  it('works', () => {})\\n});"}

  """
  def insert_test(target_code, test_code, language) when is_atom(language) do
    # Convert language atom to string and infer framework
    language_str = Atom.to_string(language)
    framework = infer_framework(language, test_code)

    trimmed_test = String.trim(test_code)

    # If this is already a complete test block for certain languages/frameworks,
    # try to integrate it via AST. This preserves existing block structure
    # and avoids wrapping complete blocks in extra describe blocks.
    is_complete_block =
      (language == :ruby and
         (String.starts_with?(trimmed_test, "it ") or
            String.starts_with?(trimmed_test, "specify ") or
            String.starts_with?(trimmed_test, "example "))) or
        (language in [:javascript, :typescript] and
           (String.starts_with?(trimmed_test, "it(") or
              String.starts_with?(trimmed_test, "test(") or
              String.starts_with?(trimmed_test, "specify(")))

    if is_complete_block do
      # For complete blocks, append directly to avoid parser issues with edge cases
      {:ok, "#{target_code}\n\n#{test_code}"}
    else
      # For test bodies, use full AST integration
      test_suite = %{
        "redTests" => [
          %{
            "testName" => "inserted test",
            "testCode" => test_code,
            "attackVector" => ""
          }
        ]
      }

      case generate_integration(target_code, test_suite, language_str, framework) do
        {:ok, integrated_code, _insertion_point, _method} ->
          {:ok, integrated_code}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  # Infer framework from language and test code patterns
  defp infer_framework(:javascript, _test_code), do: "jest"
  defp infer_framework(:typescript, _test_code), do: "jest"
  defp infer_framework(:ruby, _test_code), do: "rspec"
  defp infer_framework(:python, _test_code), do: "pytest"
  defp infer_framework(_, _), do: "jest"

  @doc """
  Parse code and return AST.

  Public wrapper around internal parse_code function for testing purposes.

  ## Parameters

  - `content`: The source code to parse as a string
  - `language`: Language atom (`:javascript`, `:ruby`, `:python`, etc.)

  ## Examples

      iex> parse("describe('Foo', () => {});", :javascript)
      {:ok, ast}

  """
  def parse(content, language) when is_atom(language) do
    language_str = Atom.to_string(language)
    parse_code(content, language_str)
  end

  @doc """
  Generates integrated test file content by inserting test suite into target file.

  Returns `{:ok, integrated_content, insertion_point, method}` where method is
  either "ast" (successful AST integration) or "append" (fallback).

  ## Parameters

  - `target_content`: The existing test file content as a string
  - `test_suite`: Map with "redTests" array containing test definitions
  - `language`: Language of the test file ("javascript" or "typescript")
  - `framework`: Test framework name ("vitest", "jest", or "mocha")

  ## Examples

      iex> generate_integration("describe('Foo', () => {});", %{"redTests" => [...]}, "javascript", "vitest")
      {:ok, "describe('Foo', () => {\\n  // ... new test ...\\n});", %{line: 2}, "ast"}

  """
  def generate_integration(target_content, test_suite, language, framework) do
    Logger.info("TestIntegrator: Starting integration for #{language}/#{framework}")

    Logger.debug(
      "Target content length: #{byte_size(target_content)}, test suite: #{inspect(test_suite)}"
    )

    with {:ok, ast} <- parse_code(target_content, language),
         {:ok, insertion_point} <- find_insertion_point(ast, framework),
         {:ok, integrated_code} <-
           insert_test(ast, test_suite, language, framework, insertion_point, target_content) do
      Logger.info("TestIntegrator: Successfully integrated test using AST")
      {:ok, integrated_code, insertion_point, "ast"}
    else
      error ->
        Logger.warning(
          "TestIntegrator: AST integration failed (#{inspect(error)}), falling back to append"
        )

        # For fallback, use default insertion_point (module level, no parent)
        fallback_insertion_point = %{parent: "module"}

        fallback_content =
          "#{target_content}\n\n#{format_test_code(test_suite, language, framework, fallback_insertion_point)}"

        {:ok, fallback_content, nil, "append"}
    end
  end

  # Parse code using existing parser infrastructure
  defp parse_code(content, language) do
    Logger.debug("TestIntegrator: Parsing #{language} code")

    with :ok <- Validators.validate_content(language, content),
         {:ok, session} <- SessionManager.create_session("test-integrator"),
         {:ok, %{ast: ast, error: nil}} <-
           ParserRegistry.parse_code(session.id, "test-integrator", language, content) do
      Logger.debug("TestIntegrator: Successfully parsed code")
      # Debug: write AST to file for inspection
      if language in ["ruby", "python"] do
        File.write!("/tmp/ast_debug_#{language}.json", JSON.encode!(ast))
      end

      {:ok, ast}
    else
      {:ok, %{error: error}} ->
        Logger.error("TestIntegrator: Parser returned error: #{inspect(error)}")
        {:error, {:parser_error, error}}

      {:error, reason} = error ->
        Logger.error("TestIntegrator: Parser failed: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Finds the best insertion point in the AST for the new test.

  Delegates to language-specific modules for AST navigation.

  ## Examples

      iex> find_insertion_point(vitest_ast, "vitest")
      {:ok, %{line: 42, strategy: "after_last_it_block", parent: "describe_block"}}

  """
  def find_insertion_point(ast, framework) when framework in @supported_frameworks do
    Languages.JavaScript.find_insertion_point(ast, framework)
  end

  def find_insertion_point(ast, "rspec") do
    Languages.Ruby.find_insertion_point(ast)
  end

  def find_insertion_point(ast, "pytest") do
    Languages.Python.find_insertion_point(ast)
  end

  def find_insertion_point(_ast, framework) do
    Logger.error("TestIntegrator: Unsupported framework: #{framework}")
    {:error, {:unsupported_framework, framework}}
  end

  @doc """
  Inserts test suite into the target file at the specified insertion point.

  Since we can't easily manipulate the Babel AST directly in Elixir,
  we use a simple string-based insertion approach that inserts the formatted
  test code at the right line number.

  ## Examples

      iex> insert_test(ast, test_suite, "javascript", "vitest", insertion_point, original_content)
      {:ok, updated_code}

  """
  def insert_test(_ast, test_suite, language, framework, insertion_point, original_content) do
    Logger.debug("TestIntegrator: Inserting test at line #{insertion_point.line}")

    # Format the new test code (pass insertion_point for context-aware formatting)
    test_code = format_test_code(test_suite, language, framework, insertion_point)

    # Split original content by lines
    lines = String.split(original_content, "\n")

    # Find the indentation of the insertion point
    indent = detect_indentation(lines, insertion_point.line, language, insertion_point.parent)

    # Indent the test code
    indented_test = indent_code(test_code, indent)

    # Insert the test code at the specified line
    {before_lines, after_lines} = Enum.split(lines, insertion_point.line)

    integrated_lines = before_lines ++ ["\n" <> indented_test] ++ after_lines
    integrated_code = Enum.join(integrated_lines, "\n")

    {:ok, integrated_code}
  end

  # Detect indentation level at a given line
  # For Python test classes, use standard 4-space indentation for methods
  defp detect_indentation(_lines, _line_number, "python", "test_class") do
    # Python PEP 8 standard: 4 spaces for class methods
    4
  end

  defp detect_indentation(lines, line_number, _language, _parent) do
    # For other cases, detect from the previous non-empty line
    lines
    |> Enum.take(line_number)
    |> Enum.reverse()
    |> Enum.find(fn line -> String.trim(line) != "" end)
    |> case do
      nil ->
        @default_indent

      line ->
        # If the line is a method/function definition, use its indentation
        # If it's a method body, look for "def " or "it(" patterns
        cond do
          # Python method definition
          String.match?(line, ~r/^\s*(async\s+)?def\s+/) ->
            case Regex.run(~r/^(\s*)/, line) do
              [_, spaces] -> byte_size(spaces)
              _ -> @default_indent
            end

          # JavaScript/Ruby test blocks
          String.match?(line, ~r/^\s*(it|test|describe|context)\s*[\(\']/) ->
            case Regex.run(~r/^(\s*)/, line) do
              [_, spaces] -> byte_size(spaces)
              _ -> @default_indent
            end

          # Default: use previous line indentation
          true ->
            case Regex.run(~r/^(\s*)/, line) do
              [_, spaces] -> byte_size(spaces)
              _ -> @default_indent
            end
        end
    end
  end

  # Indent code by adding spaces to each line
  defp indent_code(code, indent_level) do
    spaces = String.duplicate(" ", indent_level)

    code
    |> String.split("\n")
    |> Enum.map(fn
      "" -> ""
      line -> spaces <> line
    end)
    |> Enum.join("\n")
  end

  # Format test code - delegate to language-specific formatters
  defp format_test_code(%{"redTests" => red_tests}, _language, framework, insertion_point)
       when framework in ~w(vitest jest mocha) do
    Formatters.JavaScript.format_tests(red_tests, insertion_point)
  end

  defp format_test_code(%{"redTests" => red_tests}, "ruby", "rspec", insertion_point) do
    Formatters.Ruby.format_tests(red_tests, insertion_point)
  end

  defp format_test_code(%{"redTests" => red_tests}, "python", "pytest", insertion_point) do
    Formatters.Python.format_tests(red_tests, insertion_point)
  end

  defp format_test_code(test_suite, _language, _framework, _insertion_point) do
    Logger.warning("TestIntegrator: Unexpected test suite format: #{inspect(test_suite)}")
    "// Failed to format test - manual integration required"
  end
end
