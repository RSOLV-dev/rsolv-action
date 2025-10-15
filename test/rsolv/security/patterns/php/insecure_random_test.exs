defmodule Rsolv.Security.Patterns.Php.InsecureRandomTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Php.InsecureRandom
  alias Rsolv.Security.Pattern

  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = InsecureRandom.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "php-insecure-random"
      assert pattern.name == "Insecure Random Number Generation"
      assert pattern.severity == :medium
      assert pattern.type == :insecure_random
      assert pattern.languages == ["php"]
    end

    test "includes CWE and OWASP references" do
      pattern = InsecureRandom.pattern()

      assert pattern.cwe_id == "CWE-338"
      assert pattern.owasp_category == "A02:2021"
    end
  end

  describe "regex matching" do
    setup do
      pattern = InsecureRandom.pattern()
      {:ok, pattern: pattern}
    end

    test "matches insecure rand() usage", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$token = rand(1000, 9999);|,
        ~S|$session_id = rand();|,
        ~S|$nonce = rand(100000, 999999);|,
        ~S|$code = rand(10, 99);|,
        ~S|rand(1, 1000000)|
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end

    test "matches insecure mt_rand() usage", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$token = mt_rand(1000, 9999);|,
        ~S|$session_id = mt_rand();|,
        ~S|$random = mt_rand(1, 100);|,
        ~S|mt_rand(0, 999999)|
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end

    test "matches insecure seeding functions", %{pattern: pattern} do
      vulnerable_code = [
        ~S|srand(time());|,
        ~S|mt_srand(12345);|,
        ~S|srand();|,
        ~S|mt_srand(time() + getmypid());|
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end

    test "does not match secure random functions", %{pattern: pattern} do
      safe_code = [
        ~S|$token = random_int(1000, 9999);|,
        ~S|$bytes = random_bytes(16);|,
        ~S|$secure = bin2hex(random_bytes(32));|,
        ~S|$token = openssl_random_pseudo_bytes(16);|,
        ~S|$code = random_int(100000, 999999);|
      ]

      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end
  end

  describe "test_cases/0" do
    test "all positive cases match" do
      pattern = InsecureRandom.pattern()
      test_cases = InsecureRandom.test_cases()

      for test_case <- test_cases.positive do
        assert Regex.match?(pattern.regex, test_case.code),
               "Failed to match positive case: #{test_case.description}"
      end
    end

    test "negative cases are documented correctly" do
      test_cases = InsecureRandom.test_cases()

      assert length(test_cases.negative) > 0

      for test_case <- test_cases.negative do
        assert Map.has_key?(test_case, :code)
        assert Map.has_key?(test_case, :description)
      end
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = InsecureRandom.ast_enhancement()

      assert enhancement.min_confidence >= 0.7
      assert length(enhancement.ast_rules) >= 3

      insecure_functions_rule =
        Enum.find(enhancement.ast_rules, &(&1.type == "insecure_functions"))

      assert insecure_functions_rule
      assert "rand" in insecure_functions_rule.functions

      secure_alternatives_rule =
        Enum.find(enhancement.ast_rules, &(&1.type == "secure_alternatives"))

      assert secure_alternatives_rule
      assert "random_int" in secure_alternatives_rule.functions
    end
  end

  describe "pattern metadata" do
    test "has proper OWASP reference" do
      pattern = InsecureRandom.pattern()
      assert pattern.owasp_category == "A02:2021"
    end

    test "has educational content" do
      desc = InsecureRandom.vulnerability_description()
      assert desc =~ "random"
      assert desc =~ "predictable"
      assert desc =~ "security"
    end

    test "provides safe alternatives" do
      examples = InsecureRandom.examples()
      assert Map.has_key?(examples.fixed, "Using random_int()")
      assert Map.has_key?(examples.fixed, "Using random_bytes()")
    end
  end
end
