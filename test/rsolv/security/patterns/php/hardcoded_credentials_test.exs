defmodule Rsolv.Security.Patterns.Php.HardcodedCredentialsTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Php.HardcodedCredentials
  alias Rsolv.Security.Pattern

  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = HardcodedCredentials.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "php-hardcoded-credentials"
      assert pattern.name == "Hardcoded Credentials"
      assert pattern.severity == :critical
      assert pattern.type == :hardcoded_secret
      assert pattern.languages == ["php"]
    end

    test "includes CWE and OWASP references" do
      pattern = HardcodedCredentials.pattern()

      assert pattern.cwe_id == "CWE-798"
      assert pattern.owasp_category == "A07:2021"
    end
  end

  describe "regex matching" do
    setup do
      pattern = HardcodedCredentials.pattern()
      {:ok, pattern: pattern}
    end

    test "matches hardcoded database passwords", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$password = "admin123";|,
        ~S|$db_password = 'secretpassword';|,
        ~S|$mysql_pwd = "root123";|,
        ~S|define('DB_PASSWORD', 'mysecret');|
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end

    test "matches hardcoded API keys", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$api_key = "sk-1234567890abcdef";|,
        ~S|$apiKey = '4f7d3e2a9b8c1d6e5f4a3b2c1d';|,
        ~S|$secret_key = "AKIAIOSFODNN7EXAMPLE";|,
        ~S|define('API_KEY', 'abc123xyz789');|
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end

    test "matches hardcoded tokens and secrets", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";|,
        ~S|$secret = 'my_secret_string_123';|,
        ~S|$auth_token = "Bearer abc123def456";|,
        ~S|define('SECRET_TOKEN', 'xyz789abc123');|
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end

    test "matches hardcoded credentials in arrays", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$config = ['password' => 'admin123'];|,
        ~S|$db = array('password' => 'secret');|,
        ~S|'api_key' => 'sk-1234567890',|
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end

    test "does not match environment variables or config calls", %{pattern: pattern} do
      safe_code = [
        ~S|$password = $_ENV['DB_PASSWORD'];|,
        ~S|$api_key = getenv('API_KEY');|,
        ~S|$secret = config('app.secret');|,
        ~S|$token = env('AUTH_TOKEN');|,
        ~S|$pwd = file_get_contents('.env');|,
        ~S|$key = '';  // Empty string|
      ]

      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end
  end

  describe "test_cases/0" do
    test "all positive cases match" do
      pattern = HardcodedCredentials.pattern()
      test_cases = HardcodedCredentials.test_cases()

      for test_case <- test_cases.positive do
        assert Regex.match?(pattern.regex, test_case.code),
               "Failed to match positive case: #{test_case.description}"
      end
    end

    test "negative cases are documented correctly" do
      test_cases = HardcodedCredentials.test_cases()

      assert length(test_cases.negative) > 0

      for test_case <- test_cases.negative do
        assert Map.has_key?(test_case, :code)
        assert Map.has_key?(test_case, :description)
      end
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = HardcodedCredentials.ast_enhancement()

      assert enhancement.min_confidence >= 0.8
      assert length(enhancement.ast_rules) >= 3

      credential_indicators_rule =
        Enum.find(enhancement.ast_rules, &(&1.type == "credential_indicators"))

      assert credential_indicators_rule
      assert "password" in credential_indicators_rule.keywords

      safe_patterns_rule = Enum.find(enhancement.ast_rules, &(&1.type == "safe_patterns"))
      assert safe_patterns_rule
      assert "getenv" in safe_patterns_rule.functions
    end
  end

  describe "pattern metadata" do
    test "has proper OWASP reference" do
      pattern = HardcodedCredentials.pattern()
      assert pattern.owasp_category == "A07:2021"
    end

    test "has educational content" do
      desc = HardcodedCredentials.vulnerability_description()
      assert desc =~ "hardcoded"
      assert desc =~ "credentials"
      assert desc =~ "environment"
    end

    test "provides safe alternatives" do
      examples = HardcodedCredentials.examples()
      assert Map.has_key?(examples.fixed, "Using environment variables")
      assert Map.has_key?(examples.fixed, "Configuration file approach")
    end
  end
end
