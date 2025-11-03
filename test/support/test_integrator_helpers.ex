defmodule Rsolv.AST.TestIntegratorHelpers do
  @moduledoc """
  Test helpers for TestIntegrator tests.

  Provides factories for common test data and assertion helpers
  to reduce duplication across test files.
  """

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
  def build_test_suite(red_tests) when is_list(red_tests) do
    %{"redTests" => red_tests}
  end

  @doc "Builds an empty test suite"
  def empty_test_suite, do: %{"redTests" => []}

  @doc """
  Creates a red test map.

  ## Examples

      iex> red_test("validates input", "expect(true).toBe(true)", "test")
      %{"testName" => "validates input", "testCode" => "expect(true).toBe(true)", "attackVector" => "test"}
  """
  def red_test(name, code, attack_vector) do
    %{
      "testName" => name,
      "testCode" => code,
      "attackVector" => attack_vector
    }
  end

  # ============================================================================
  # Common Test Examples
  # ============================================================================

  @doc "SQL injection test for JavaScript"
  def sql_injection_js do
    red_test(
      "prevents SQL injection",
      "const result = query(\"' OR '1'='1\");\nexpect(result).toBeNull();",
      "' OR '1'='1"
    )
  end

  @doc "SQL injection test for Ruby"
  def sql_injection_ruby do
    red_test(
      "prevents SQL injection",
      "result = query(\"' OR '1'='1\")\nexpect(result).to be_nil",
      "' OR '1'='1"
    )
  end

  @doc "SQL injection test for Python"
  def sql_injection_python do
    red_test(
      "prevents SQL injection",
      "result = query(\"' OR '1'='1\")\nassert result is None",
      "' OR '1'='1"
    )
  end

  @doc "Path traversal test for JavaScript"
  def path_traversal_js do
    red_test(
      "prevents path traversal",
      "const result = readFile('../../../etc/passwd');\nexpect(result).toBeNull();",
      "../../../etc/passwd"
    )
  end

  @doc "Path traversal test for Ruby"
  def path_traversal_ruby do
    red_test(
      "prevents path traversal",
      "result = read_file('../../../etc/passwd')\nexpect(result).to be_nil",
      "../../../etc/passwd"
    )
  end

  @doc "Path traversal test for Python"
  def path_traversal_python do
    red_test(
      "prevents path traversal",
      "result = read_file('../../../etc/passwd')\nassert result is None",
      "../../../etc/passwd"
    )
  end

  @doc "XSS test for JavaScript"
  def xss_js do
    red_test(
      "prevents XSS attack",
      "const result = render('<script>alert(\"XSS\")</script>');\nexpect(result).not.toContain('<script>');",
      "<script>alert(\"XSS\")</script>"
    )
  end

  @doc "XSS test for Ruby"
  def xss_ruby do
    red_test(
      "prevents XSS attack",
      "result = render('<script>alert(\"XSS\")</script>')\nexpect(result).not_to include('<script>')",
      "<script>alert(\"XSS\")</script>"
    )
  end

  @doc "XSS test for Python"
  def xss_python do
    red_test(
      "prevents XSS attack",
      "result = render('<script>alert(\"XSS\")</script>')\nassert '<script>' not in result",
      "<script>alert(\"XSS\")</script>"
    )
  end

  # ============================================================================
  # Malformed Code Examples
  # ============================================================================

  @doc "Unclosed JavaScript describe block"
  def malformed_js do
    """
    describe('Test', () => { // unclosed describe block
    """
  end

  @doc "Unclosed Ruby RSpec block"
  def malformed_ruby do
    """
    RSpec.describe 'Test' do # unclosed block
    """
  end

  @doc "Unclosed Python class"
  def malformed_python do
    """
    class TestFoo:  # unclosed class
        def test_bar(self
    """
  end

  # ============================================================================
  # Assertion Helpers
  # ============================================================================

  @doc """
  Asserts successful AST integration.

  Checks that:
  - Method is "ast"
  - Insertion point exists with expected strategy
  - All expected strings are in the integrated code
  """
  def assert_ast_integration(
        result,
        expected_strategy,
        expected_strings \\ []
      ) do
    import ExUnit.Assertions

    {:ok, integrated_code, insertion_point, method} = result

    assert method == "ast", "Expected AST integration method"
    assert insertion_point != nil, "Expected insertion point"
    assert insertion_point.strategy == expected_strategy

    for string <- expected_strings do
      assert String.contains?(integrated_code, string),
             "Expected integrated code to contain: #{string}"
    end

    {:ok, integrated_code}
  end

  @doc """
  Asserts fallback to append mode.

  Checks that:
  - Method is "append"
  - Insertion point is nil
  - Expected strings are in the integrated code
  """
  def assert_fallback_append(result, expected_strings \\ []) do
    import ExUnit.Assertions

    {:ok, integrated_code, insertion_point, method} = result

    assert method == "append", "Expected append fallback method"
    assert insertion_point == nil, "Expected nil insertion point for append"

    for string <- expected_strings do
      assert String.contains?(integrated_code, string),
             "Expected integrated code to contain: #{string}"
    end

    {:ok, integrated_code}
  end

  @doc """
  Asserts code contains all given strings.
  """
  def assert_contains_all(code, strings) when is_list(strings) do
    import ExUnit.Assertions

    for string <- strings do
      assert String.contains?(code, string),
             "Expected code to contain: #{string}"
    end

    code
  end

  @doc """
  Runs integration and asserts AST method with specific assertions.
  """
  def integrate_and_assert_ast(
        target_content,
        test_suite,
        language,
        framework,
        opts \\ []
      ) do
    strategy = Keyword.get(opts, :strategy, "after_last_it_block")
    contains = Keyword.get(opts, :contains, [])

    result = TestIntegrator.generate_integration(target_content, test_suite, language, framework)
    assert_ast_integration(result, strategy, contains)
  end

  @doc """
  Runs integration and asserts fallback to append.
  """
  def integrate_and_assert_fallback(
        target_content,
        test_suite,
        language,
        framework,
        expected_strings \\ []
      ) do
    result = TestIntegrator.generate_integration(target_content, test_suite, language, framework)
    assert_fallback_append(result, expected_strings)
  end
end
