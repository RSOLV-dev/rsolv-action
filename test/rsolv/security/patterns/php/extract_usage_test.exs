defmodule Rsolv.Security.Patterns.Php.ExtractUsageTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Php.ExtractUsage
  alias Rsolv.Security.Pattern

  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = ExtractUsage.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "php-extract-usage"
      assert pattern.name == "Variable Overwrite via extract()"
      assert pattern.severity == :high
      assert pattern.type == :input_validation
      assert pattern.languages == ["php"]
    end

    test "includes CWE and OWASP references" do
      pattern = ExtractUsage.pattern()

      assert pattern.cwe_id == "CWE-621"
      assert pattern.owasp_category == "A03:2021"
    end
  end

  describe "regex matching" do
    setup do
      pattern = ExtractUsage.pattern()
      {:ok, pattern: pattern}
    end

    test "matches extract with direct user input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|extract($_POST);|,
        ~S|extract($_GET);|,
        ~S|extract($_REQUEST);|,
        ~S|extract($_COOKIE);|
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end

    test "matches extract with array access syntax", %{pattern: pattern} do
      vulnerable_code = [
        ~S|extract($_POST['data']);|,
        ~S|extract($_GET["params"]);|,
        ~S|extract($_REQUEST['vars']);|,
        ~S|extract($_COOKIE['settings']);|
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end

    test "matches various extract syntax variations", %{pattern: pattern} do
      vulnerable_code = [
        ~S|extract( $_POST );|,
        ~S|extract($_GET, EXTR_OVERWRITE);|,
        ~S|extract($_REQUEST, EXTR_PREFIX_ALL, "user");|,
        ~S|extract($_COOKIE);|
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end

    test "does not match safe operations", %{pattern: pattern} do
      safe_code = [
        ~S|extract($safe_data);|,
        ~S|extract($_POST, EXTR_SKIP);|,
        ~S|$name = $_POST['name'];|,
        ~S|echo "extract is dangerous with $_POST";|,
        ~S|$extract = $_POST['data'];|
      ]

      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end

    test "matches commented extract (requires AST to exclude)", %{pattern: pattern} do
      # Comment detection requires AST analysis
      # Simple regex will match this as a false positive
      commented_code = ~S|// extract($_POST);|

      assert Regex.match?(pattern.regex, commented_code),
             "Regex matches commented code (AST needed to exclude)"
    end

    test "matches real-world vulnerable patterns", %{pattern: pattern} do
      vulnerable_code = [
        ~S|extract($_POST, EXTR_OVERWRITE);|,
        ~S|extract($_GET, EXTR_PREFIX_SAME, "p");|,
        ~S|extract($_REQUEST, EXTR_IF_EXISTS);|
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
  end

  describe "test_cases/0" do
    test "all positive cases match" do
      pattern = ExtractUsage.pattern()
      test_cases = ExtractUsage.test_cases()

      for test_case <- test_cases.positive do
        assert Regex.match?(pattern.regex, test_case.code),
               "Failed to match positive case: #{test_case.description}"
      end
    end

    test "negative cases are documented correctly" do
      test_cases = ExtractUsage.test_cases()

      assert length(test_cases.negative) > 0

      for test_case <- test_cases.negative do
        assert Map.has_key?(test_case, :code)
        assert Map.has_key?(test_case, :description)
      end
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = ExtractUsage.ast_enhancement()

      assert enhancement.min_confidence >= 0.7
      assert length(enhancement.ast_rules) >= 3

      functions_rule = Enum.find(enhancement.ast_rules, &(&1.type == "extract_functions"))
      assert functions_rule
      assert "extract" in functions_rule.functions

      user_input_rule = Enum.find(enhancement.ast_rules, &(&1.type == "user_input_analysis"))
      assert user_input_rule
      assert "$_GET" in user_input_rule.dangerous_sources
      assert "$_POST" in user_input_rule.dangerous_sources
    end
  end

  describe "pattern metadata" do
    test "has proper OWASP reference" do
      pattern = ExtractUsage.pattern()
      assert pattern.owasp_category == "A03:2021"
    end

    test "has educational content" do
      desc = ExtractUsage.vulnerability_description()
      assert desc =~ "extract"
      assert desc =~ "variable"
      assert desc =~ "overwrite"
    end

    test "provides safe alternatives" do
      examples = ExtractUsage.examples()
      assert Map.has_key?(examples.fixed, "Direct access")
      assert Map.has_key?(examples.fixed, "EXTR_SKIP flag")
    end
  end
end
