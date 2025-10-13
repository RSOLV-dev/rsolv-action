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
  require Logger

  @supported_frameworks ~w(vitest jest mocha)
  @test_function_names ~w(it test specify)
  @describe_function_names ~w(describe context suite)
  @default_indent 2

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
    Logger.debug("Target content length: #{byte_size(target_content)}, test suite: #{inspect(test_suite)}")

    with {:ok, ast} <- parse_code(target_content, language),
         {:ok, insertion_point} <- find_insertion_point(ast, framework),
         {:ok, integrated_code} <- insert_test(ast, test_suite, language, framework, insertion_point, target_content) do
      Logger.info("TestIntegrator: Successfully integrated test using AST")
      {:ok, integrated_code, insertion_point, "ast"}
    else
      error ->
        Logger.warning("TestIntegrator: AST integration failed (#{inspect(error)}), falling back to append")
        fallback_content = "#{target_content}\n\n#{format_test_code(test_suite, language, framework)}"
        {:ok, fallback_content, nil, "append"}
    end
  end

  # Parse code using existing parser infrastructure
  defp parse_code(content, language) do
    Logger.debug("TestIntegrator: Parsing #{language} code")

    with {:ok, session} <- SessionManager.create_session("test-integrator"),
         {:ok, %{ast: ast, error: nil}} <- ParserRegistry.parse_code(session.id, "test-integrator", language, content) do
      Logger.debug("TestIntegrator: Successfully parsed code")
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

  Returns insertion point metadata with line number and strategy.

  For Jest/Vitest/Mocha, we look for the last `it()` or `test()` block
  inside the outermost `describe()` block.

  ## Examples

      iex> find_insertion_point(vitest_ast, "vitest")
      {:ok, %{line: 42, strategy: "after_last_it_block", parent: "describe_block"}}

  """
  def find_insertion_point(ast, framework) when framework in @supported_frameworks do
    Logger.debug("TestIntegrator: Finding insertion point for #{framework}")

    # Find the outermost describe block
    case find_outermost_describe(ast) do
      nil ->
        Logger.warning("TestIntegrator: No describe block found")
        {:error, :no_describe_block}

      describe_node ->
        # Find the last test block (it/test) within the describe
        case find_last_test_block(describe_node) do
          nil ->
            Logger.warning("TestIntegrator: No test blocks found in describe")
            # Insert at the end of describe block, before closing brace
            {:ok, %{
              line: get_node_end_line(describe_node) - 1,
              strategy: "inside_describe_block",
              parent: "describe_block"
            }}

          last_test ->
            # Insert after the last test block
            line = get_node_end_line(last_test) + 1
            Logger.debug("TestIntegrator: Found insertion point at line #{line}")
            {:ok, %{
              line: line,
              strategy: "after_last_it_block",
              parent: "describe_block"
            }}
        end
    end
  end

  def find_insertion_point(_ast, framework) do
    Logger.error("TestIntegrator: Unsupported framework: #{framework}")
    {:error, {:unsupported_framework, framework}}
  end

  # Find the outermost describe block in the AST
  defp find_outermost_describe(%{"type" => "File", "program" => program}),
    do: find_outermost_describe(program)

  defp find_outermost_describe(%{"type" => "Program", "body" => body}) when is_list(body),
    do: Enum.find_value(body, &find_describe_in_statement/1)

  defp find_outermost_describe(_), do: nil

  # Find describe block in a statement
  defp find_describe_in_statement(%{"type" => "ExpressionStatement", "expression" => expr}),
    do: find_describe_in_expression(expr)

  defp find_describe_in_statement(_), do: nil

  # Find describe in call expression
  defp find_describe_in_expression(%{
    "type" => "CallExpression",
    "callee" => %{"type" => "Identifier", "name" => name}
  } = node) when name in @describe_function_names, do: node

  defp find_describe_in_expression(_), do: nil

  # Find the last test block (it/test) within a describe
  defp find_last_test_block(%{"arguments" => arguments}) when is_list(arguments) do
    # The second argument should be the function containing test blocks
    case Enum.at(arguments, 1) do
      %{"type" => type, "body" => body} when type in ["FunctionExpression", "ArrowFunctionExpression"] ->
        find_last_test_in_body(body)

      _ ->
        nil
    end
  end

  defp find_last_test_block(_), do: nil

  # Find last test in function body
  defp find_last_test_in_body(%{"type" => "BlockStatement", "body" => statements}) when is_list(statements) do
    statements
    |> Enum.reverse()
    |> Enum.find_value(&find_test_in_statement/1)
  end

  defp find_last_test_in_body(_), do: nil

  # Find test in statement
  defp find_test_in_statement(%{
    "type" => "ExpressionStatement",
    "expression" => %{
      "type" => "CallExpression",
      "callee" => %{"type" => "Identifier", "name" => name}
    } = node
  }) when name in @test_function_names, do: node

  defp find_test_in_statement(_), do: nil

  # Get end line of a node
  defp get_node_end_line(%{"_loc" => %{"end" => %{"line" => line}}}), do: line
  defp get_node_end_line(%{"loc" => %{"end" => %{"line" => line}}}), do: line
  defp get_node_end_line(_), do: 1

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

    # Format the new test code
    test_code = format_test_code(test_suite, language, framework)

    # Split original content by lines
    lines = String.split(original_content, "\n")

    # Find the indentation of the insertion point
    indent = detect_indentation(lines, insertion_point.line)

    # Indent the test code
    indented_test = indent_code(test_code, indent)

    # Insert the test code at the specified line
    {before_lines, after_lines} = Enum.split(lines, insertion_point.line)

    integrated_lines = before_lines ++ ["\n" <> indented_test] ++ after_lines
    integrated_code = Enum.join(integrated_lines, "\n")

    {:ok, integrated_code}
  end

  # Detect indentation level at a given line
  defp detect_indentation(lines, line_number) do
    lines
    |> Enum.at(max(0, line_number - 1))
    |> case do
      nil -> @default_indent
      line ->
        case Regex.run(~r/^(\s*)/, line) do
          [_, spaces] -> byte_size(spaces)
          _ -> @default_indent
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

  # Format test code for Jest/Vitest/Mocha
  defp format_test_code(%{"redTests" => red_tests}, _language, framework)
      when framework in @supported_frameworks do
    red_tests
    |> Enum.map(&format_single_test/1)
    |> wrap_in_describe_block()
  end

  defp format_test_code(test_suite, _language, _framework) do
    Logger.warning("TestIntegrator: Unexpected test suite format: #{inspect(test_suite)}")
    "// Failed to format test - manual integration required"
  end

  # Format a single test block
  defp format_single_test(%{"testName" => name, "testCode" => code, "attackVector" => vector}) do
    """
    it('#{name}', () => {
      // Attack vector: #{vector}
      #{indent_test_body(code)}
    });
    """
  end

  # Wrap test blocks in describe('security') block
  defp wrap_in_describe_block(test_blocks) do
    """
    describe('security', () => {
    #{Enum.join(test_blocks, "\n")}
    });
    """
  end

  # Indent test body (add 2 spaces to each line)
  defp indent_test_body(code) do
    code
    |> String.split("\n")
    |> Enum.map(&("  " <> &1))
    |> Enum.join("\n")
  end
end
