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
  # Ruby-specific
  @ruby_describe_names ~w(describe context)
  @ruby_test_names ~w(it specify example)
  # Python-specific
  @python_test_prefix "test_"
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

    with {:ok, session} <- SessionManager.create_session("test-integrator"),
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
            {:ok,
             %{
               line: get_node_end_line(describe_node) - 1,
               strategy: "inside_describe_block",
               parent: "describe_block"
             }}

          last_test ->
            # Insert after the last test block
            line = get_node_end_line(last_test) + 1
            Logger.debug("TestIntegrator: Found insertion point at line #{line}")

            {:ok,
             %{
               line: line,
               strategy: "after_last_it_block",
               parent: "describe_block"
             }}
        end
    end
  end

  # RSpec insertion point logic
  def find_insertion_point(ast, "rspec") do
    Logger.debug("TestIntegrator: Finding insertion point for RSpec")

    case find_ruby_outermost_describe(ast) do
      nil ->
        Logger.warning("TestIntegrator: No describe block found in RSpec file")
        {:error, :no_describe_block}

      describe_node ->
        case find_ruby_last_test_block(describe_node) do
          nil ->
            Logger.warning("TestIntegrator: No test blocks found in describe")

            {:ok,
             %{
               line: get_node_end_line(describe_node) - 1,
               strategy: "inside_describe_block",
               parent: "describe_block"
             }}

          last_test ->
            line = get_node_end_line(last_test) + 1
            Logger.debug("TestIntegrator: Found RSpec insertion point at line #{line}")

            {:ok,
             %{
               line: line,
               strategy: "after_last_it_block",
               parent: "describe_block"
             }}
        end
    end
  end

  # pytest insertion point logic
  def find_insertion_point(ast, "pytest") do
    Logger.debug("TestIntegrator: Finding insertion point for pytest")

    case find_python_test_container(ast) do
      nil ->
        Logger.warning("TestIntegrator: No test class or function found in pytest file")
        {:error, :no_test_container}

      {container_type, container_node, last_test} ->
        line =
          if last_test,
            do: get_node_end_line(last_test) + 1,
            else: get_node_end_line(container_node) - 1

        Logger.debug(
          "TestIntegrator: Found pytest insertion point at line #{line} (#{container_type})"
        )

        {:ok,
         %{
           line: line,
           strategy: "after_last_test_function",
           parent: container_type
         }}
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
  defp find_describe_in_expression(
         %{
           "type" => "CallExpression",
           "callee" => %{"type" => "Identifier", "name" => name}
         } = node
       )
       when name in @describe_function_names,
       do: node

  defp find_describe_in_expression(_), do: nil

  # Find the last test block (it/test) within a describe
  defp find_last_test_block(%{"arguments" => arguments}) when is_list(arguments) do
    # The second argument should be the function containing test blocks
    case Enum.at(arguments, 1) do
      %{"type" => type, "body" => body}
      when type in ["FunctionExpression", "ArrowFunctionExpression"] ->
        find_last_test_in_body(body)

      _ ->
        nil
    end
  end

  defp find_last_test_block(_), do: nil

  # Find last test in function body
  defp find_last_test_in_body(%{"type" => "BlockStatement", "body" => statements})
       when is_list(statements) do
    statements
    |> Enum.reverse()
    |> Enum.find_value(&find_test_in_statement/1)
  end

  defp find_last_test_in_body(_), do: nil

  # Find test in statement
  defp find_test_in_statement(%{
         "type" => "ExpressionStatement",
         "expression" =>
           %{
             "type" => "CallExpression",
             "callee" => %{"type" => "Identifier", "name" => name}
           } = node
       })
       when name in @test_function_names,
       do: node

  defp find_test_in_statement(_), do: nil

  # Get end line of a node
  # JavaScript/TypeScript parsers use these formats
  defp get_node_end_line(%{"_loc" => %{"end" => %{"line" => line}}}), do: line
  defp get_node_end_line(%{"loc" => %{"end" => %{"line" => line}}}), do: line
  # Python parser uses _end_lineno (note: 1-indexed)
  defp get_node_end_line(%{"_end_lineno" => line}) when is_integer(line), do: line
  # Ruby parser might use different format
  defp get_node_end_line(_), do: 1

  # ============================================================================
  # Ruby AST Helper Functions (RSpec)
  # ============================================================================

  # Find outermost describe/context block in Ruby AST
  # Ruby parser returns:
  # - "begin" node with children array when file has multiple statements (e.g., require + describe)
  # - "block" node directly when file has only the describe block
  defp find_ruby_outermost_describe(%{"type" => "begin", "children" => children})
       when is_list(children),
       do: Enum.find_value(children, &find_ruby_describe_in_node/1)

  defp find_ruby_outermost_describe(%{"type" => "block"} = node),
    do: find_ruby_describe_in_node(node)

  defp find_ruby_outermost_describe(_), do: nil

  # Find describe/context block - it's a "block" node with "send" as first child
  defp find_ruby_describe_in_node(%{"type" => "block", "children" => [send_node | _]} = node) do
    case send_node do
      %{
        "type" => "send",
        "children" => [%{"type" => "const", "children" => [nil, "RSpec"]}, "describe" | _]
      } ->
        node

      %{"type" => "send", "children" => [nil, name | _]} when name in @ruby_describe_names ->
        node

      _ ->
        nil
    end
  end

  defp find_ruby_describe_in_node(_), do: nil

  # Find last it/specify/example block in Ruby describe
  # Ruby parser returns block with exactly 3 children: [send_node, args_node, body_node]
  defp find_ruby_last_test_block(%{"type" => "block", "children" => children})
       when is_list(children) and length(children) >= 3 do
    # Third child (index 2) is the body - usually a "begin" node with multiple children
    body_node = Enum.at(children, 2)

    case body_node do
      %{"type" => "begin", "children" => body_children} when is_list(body_children) ->
        # Find last test block in body
        body_children
        |> Enum.reverse()
        |> Enum.find_value(&find_ruby_test_in_node/1)

      # Body might be a single node
      single_node ->
        find_ruby_test_in_node(single_node)
    end
  end

  defp find_ruby_last_test_block(_), do: nil

  # Find it/specify/example block - it's a "block" node with "send" as first child
  defp find_ruby_test_in_node(%{"type" => "block", "children" => [send_node | _]} = node) do
    case send_node do
      %{"type" => "send", "children" => [nil, name | _]} when name in @ruby_test_names ->
        node

      _ ->
        nil
    end
  end

  defp find_ruby_test_in_node(_), do: nil

  # ============================================================================
  # Python AST Helper Functions (pytest)
  # ============================================================================

  # Find test container (class or module-level) in Python AST
  # Python parser returns "Module" (capital M) with body array
  defp find_python_test_container(%{"type" => "Module", "body" => body}) when is_list(body) do
    # Look for test class first, then fall back to module-level test functions
    case find_python_test_class(body) do
      {class_node, last_test} ->
        {"test_class", class_node, last_test}

      nil ->
        case find_python_last_module_test(body) do
          nil -> nil
          last_test -> {"module", %{"type" => "Module"}, last_test}
        end
    end
  end

  defp find_python_test_container(_), do: nil

  # Find test class (class starting with Test or containing test_ methods)
  # Python parser returns "ClassDef" with name as direct string
  defp find_python_test_class(statements) do
    test_class =
      Enum.find(statements, fn
        %{"type" => "ClassDef", "name" => name} when is_binary(name) ->
          String.starts_with?(name, "Test")

        _ ->
          false
      end)

    case test_class do
      nil ->
        nil

      %{"body" => body} when is_list(body) ->
        last_test = find_python_last_test_in_class(body)
        {test_class, last_test}
    end
  end

  # Find last test function in class body
  defp find_python_last_test_in_class(body) do
    body
    |> Enum.reverse()
    |> Enum.find(&is_python_test_function/1)
  end

  # Find last module-level test function
  defp find_python_last_module_test(statements) do
    statements
    |> Enum.reverse()
    |> Enum.find(&is_python_test_function/1)
  end

  # Check if node is a test function (starts with test_)
  # Python parser returns "FunctionDef" or "AsyncFunctionDef" with name as direct string
  defp is_python_test_function(%{
         "type" => type,
         "name" => name
       })
       when type in ["FunctionDef", "AsyncFunctionDef"] and is_binary(name) do
    String.starts_with?(name, @python_test_prefix)
  end

  defp is_python_test_function(_), do: false

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

  # Format test code for Jest/Vitest/Mocha
  defp format_test_code(%{"redTests" => red_tests}, _language, framework, _insertion_point)
       when framework in ~w(vitest jest mocha) do
    red_tests
    |> Enum.map(&format_single_js_test/1)
    |> wrap_in_js_describe_block()
  end

  # Format test code for RSpec
  defp format_test_code(%{"redTests" => red_tests}, "ruby", "rspec", _insertion_point) do
    red_tests
    |> Enum.map(&format_single_rspec_test/1)
    |> wrap_in_rspec_describe_block()
  end

  # Format test code for pytest
  defp format_test_code(%{"redTests" => red_tests}, "python", "pytest", insertion_point) do
    formatted_tests = Enum.map(red_tests, &format_single_pytest_test/1)

    # If inserting into existing test class, don't wrap in new class
    if insertion_point.parent == "test_class" do
      Enum.join(formatted_tests, "\n\n")
    else
      wrap_in_pytest_class(formatted_tests)
    end
  end

  defp format_test_code(test_suite, _language, _framework, _insertion_point) do
    Logger.warning("TestIntegrator: Unexpected test suite format: #{inspect(test_suite)}")
    "// Failed to format test - manual integration required"
  end

  # Format a single JavaScript/TypeScript test block
  defp format_single_js_test(%{"testName" => name, "testCode" => code, "attackVector" => vector}) do
    """
    it('#{name}', () => {
      // Attack vector: #{vector}
      #{indent_test_body(code)}
    });
    """
  end

  # Format a single RSpec test block
  defp format_single_rspec_test(%{
         "testName" => name,
         "testCode" => code,
         "attackVector" => vector
       }) do
    """
    it '#{name}' do
      # Attack vector: #{vector}
      #{indent_test_body(code)}
    end
    """
  end

  # Format a single pytest test function
  defp format_single_pytest_test(%{
         "testName" => name,
         "testCode" => code,
         "attackVector" => vector
       }) do
    # Check if code is already a complete function definition
    if String.starts_with?(String.trim(code), "def ") or
         String.starts_with?(String.trim(code), "async def ") do
      # Code is already a complete method - use it directly with attack vector comment
      """
      # Attack vector: #{vector}
      #{code}
      """
    else
      # Code is just test body - wrap in function definition
      # Convert test name to valid Python function name
      func_name =
        name
        |> String.downcase()
        |> String.replace(~r/[^a-z0-9_]/, "_")
        |> String.replace(~r/_+/, "_")
        |> String.trim("_")

      """
      def test_#{func_name}(self):
          \"\"\"#{name}

          Attack vector: #{vector}
          \"\"\"
          #{indent_test_body(code, 4)}
      """
    end
  end

  # Wrap test blocks in describe('security') block for JavaScript
  defp wrap_in_js_describe_block(test_blocks) do
    """
    describe('security', () => {
    #{Enum.join(test_blocks, "\n")}
    });
    """
  end

  # Wrap test blocks in describe 'security' block for RSpec
  defp wrap_in_rspec_describe_block(test_blocks) do
    """
    describe 'security' do
    #{Enum.join(test_blocks, "\n")}
    end
    """
  end

  # Wrap test functions in TestSecurity class for pytest
  defp wrap_in_pytest_class(test_functions) do
    """
    class TestSecurity:
        \"\"\"Security test suite for vulnerability validation\"\"\"

    #{Enum.join(test_functions, "\n")}
    """
  end

  # Indent test body (add specified number of spaces to each line, default 2)
  defp indent_test_body(code, spaces \\ 2) do
    indent = String.duplicate(" ", spaces)

    code
    |> String.split("\n")
    |> Enum.map(fn
      "" -> ""
      line -> indent <> line
    end)
    |> Enum.join("\n")
  end
end
