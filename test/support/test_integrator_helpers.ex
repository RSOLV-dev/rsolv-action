defmodule Rsolv.AST.TestIntegratorHelpers do
  @moduledoc """
  Test helpers for TestIntegrator tests.

  Provides factories for common test data and assertion helpers
  to reduce duplication across test files.
  """

  import ExUnit.Assertions
  alias Rsolv.AST.TestIntegrator

  # ============================================================================
  # Test Suite Builders
  # ============================================================================

  @doc """
  Builds a test suite with the given red tests.

  ## Examples

      iex> build_test_suite([red_test("validates input", "expect(true).toBe(true)", "test")])
      %{"redTests" => [%{"testName" => "validates input", ...}]}
  """
  def build_test_suite(red_tests) when is_list(red_tests), do: %{"redTests" => red_tests}

  @doc "Builds an empty test suite"
  def empty_test_suite, do: %{"redTests" => []}

  @doc """
  Creates a red test map.

  ## Examples

      iex> red_test("validates input", "expect(true).toBe(true)", "test")
      %{"testName" => "validates input", "testCode" => "expect(true).toBe(true)", "attackVector" => "test"}
  """
  def red_test(name, code, attack_vector) do
    %{"testName" => name, "testCode" => code, "attackVector" => attack_vector}
  end

  # ============================================================================
  # Common Vulnerability Tests (Generated via Metaprogramming)
  # ============================================================================

  @vulnerability_tests %{
    sql_injection: %{
      attack_vector: "' OR '1'='1",
      test_name: "prevents SQL injection",
      code: %{
        javascript: ~s|const result = query("' OR '1'='1");\nexpect(result).toBeNull();|,
        ruby: ~s|result = query("' OR '1'='1")\nexpect(result).to be_nil|,
        python: ~s|result = query("' OR '1'='1")\nassert result is None|
      }
    },
    path_traversal: %{
      attack_vector: "../../../etc/passwd",
      test_name: "prevents path traversal",
      code: %{
        javascript: ~s|const result = readFile('../../../etc/passwd');\nexpect(result).toBeNull();|,
        ruby: ~s|result = read_file('../../../etc/passwd')\nexpect(result).to be_nil|,
        python: ~s|result = read_file('../../../etc/passwd')\nassert result is None|
      }
    },
    xss: %{
      attack_vector: ~s|<script>alert("XSS")</script>|,
      test_name: "prevents XSS attack",
      code: %{
        javascript: ~s|const result = render('<script>alert("XSS")</script>');\nexpect(result).not.toContain('<script>');|,
        ruby: ~s|result = render('<script>alert("XSS")</script>')\nexpect(result).not_to include('<script>')|,
        python: ~s|result = render('<script>alert("XSS")</script>')\nassert '<script>' not in result|
      }
    }
  }

  # Generate functions for each vulnerability type and language
  for {vuln_type, config} <- @vulnerability_tests,
      {lang, code} <- config.code do
    function_name = :"#{vuln_type}_#{lang}"

    @doc """
    #{String.capitalize(to_string(vuln_type))} test for #{String.capitalize(to_string(lang))}.

    Returns a red test with attack vector: #{config.attack_vector}
    """
    def unquote(function_name)() do
      red_test(
        unquote(config.test_name),
        unquote(code),
        unquote(config.attack_vector)
      )
    end
  end

  # ============================================================================
  # Malformed Code Examples
  # ============================================================================

  @malformed_code %{
    javascript: "describe('Test', () => { // unclosed describe block\n",
    ruby: "RSpec.describe 'Test' do # unclosed block\n",
    python: "class TestFoo:  # unclosed class\n    def test_bar(self\n"
  }

  for {lang, code} <- @malformed_code do
    function_name = :"malformed_#{lang}"

    @doc "Unclosed #{String.capitalize(to_string(lang))} code for testing parser error handling"
    def unquote(function_name)(), do: unquote(code)
  end

  # Convenience aliases for common abbreviations
  def malformed_js, do: malformed_javascript()
  def malformed_rb, do: malformed_ruby()
  def malformed_py, do: malformed_python()

  # Language aliases for vulnerability tests
  def sql_injection_js, do: sql_injection_javascript()
  def path_traversal_js, do: path_traversal_javascript()
  def xss_js, do: xss_javascript()

  def sql_injection_rb, do: sql_injection_ruby()
  def path_traversal_rb, do: path_traversal_ruby()
  def xss_rb, do: xss_ruby()

  def sql_injection_py, do: sql_injection_python()
  def path_traversal_py, do: path_traversal_python()
  def xss_py, do: xss_python()

  # ============================================================================
  # Assertion Helpers
  # ============================================================================

  @doc """
  Asserts successful AST integration.

  Checks that:
  - Method is "ast"
  - Insertion point exists with expected strategy
  - All expected strings are in the integrated code

  Returns the integrated code for further assertions.
  """
  def assert_ast_integration(result, expected_strategy, expected_strings \\ []) do
    with {:ok, integrated_code, insertion_point, method} <- result do
      assert method == "ast", "Expected AST integration method"
      assert insertion_point != nil, "Expected insertion point"
      assert insertion_point.strategy == expected_strategy

      assert_contains_all(integrated_code, expected_strings)

      {:ok, integrated_code}
    end
  end

  @doc """
  Asserts fallback to append mode.

  Checks that:
  - Method is "append"
  - Insertion point is nil
  - Expected strings are in the integrated code

  Returns the integrated code for further assertions.
  """
  def assert_fallback_append(result, expected_strings \\ []) do
    with {:ok, integrated_code, insertion_point, method} <- result do
      assert method == "append", "Expected append fallback method"
      assert insertion_point == nil, "Expected nil insertion point for append"

      assert_contains_all(integrated_code, expected_strings)

      {:ok, integrated_code}
    end
  end

  @doc """
  Asserts code contains all given strings.

  Returns the code for chaining.
  """
  def assert_contains_all(code, strings) when is_list(strings) do
    Enum.each(strings, fn string ->
      assert String.contains?(code, string), "Expected code to contain: #{string}"
    end)

    code
  end

  @doc """
  Runs integration and asserts AST method with specific assertions.

  ## Options

    * `:strategy` - Expected insertion strategy (default: "after_last_it_block")
    * `:contains` - List of strings that must be in the integrated code (default: [])

  ## Examples

      integrate_and_assert_ast(content, suite, "javascript", "vitest",
        strategy: "after_last_it_block",
        contains: ["test security", "creates user"]
      )
  """
  def integrate_and_assert_ast(target_content, test_suite, language, framework, opts \\ []) do
    strategy = Keyword.get(opts, :strategy, "after_last_it_block")
    contains = Keyword.get(opts, :contains, [])

    target_content
    |> TestIntegrator.generate_integration(test_suite, language, framework)
    |> assert_ast_integration(strategy, contains)
  end

  @doc """
  Runs integration and asserts fallback to append.

  ## Examples

      integrate_and_assert_fallback(content, suite, "javascript", "vitest", [
        "test security"
      ])
  """
  def integrate_and_assert_fallback(
        target_content,
        test_suite,
        language,
        framework,
        expected_strings \\ []
      ) do
    target_content
    |> TestIntegrator.generate_integration(test_suite, language, framework)
    |> assert_fallback_append(expected_strings)
  end
end
