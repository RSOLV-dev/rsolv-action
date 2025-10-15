defmodule Rsolv.Security.Patterns.Php.MissingCsrfTokenTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Php.MissingCsrfToken
  alias Rsolv.Security.Pattern

  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = MissingCsrfToken.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "php-missing-csrf-token"
      assert pattern.name == "Missing CSRF Protection"
      assert pattern.severity == :medium
      assert pattern.type == :csrf
      assert pattern.languages == ["php"]
    end

    test "includes CWE and OWASP references" do
      pattern = MissingCsrfToken.pattern()

      assert pattern.cwe_id == "CWE-352"
      assert pattern.owasp_category == "A01:2021"
    end
  end

  describe "regex matching" do
    setup do
      pattern = MissingCsrfToken.pattern()
      {:ok, pattern: pattern}
    end

    test "matches POST method check without CSRF validation", %{pattern: pattern} do
      vulnerable_code = [
        ~s|if ($_SERVER['REQUEST_METHOD'] === 'POST') { updateProfile($_POST['email']); }|,
        ~s|if ($_SERVER['REQUEST_METHOD'] == 'POST') { deleteUser($_POST['id']); }|,
        ~s|if($_SERVER["REQUEST_METHOD"]==="POST"){changePassword($_POST['password']);}|,
        ~s|if ( $_SERVER['REQUEST_METHOD'] === "POST" ) { transferFunds($_POST['amount']); }|
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end

    test "does not match when CSRF token is checked", %{pattern: pattern} do
      safe_code = [
        ~s|if ($_SERVER['REQUEST_METHOD'] === 'POST' && validateCSRFToken($_POST['csrf_token'])) { updateProfile($_POST['email']); }|,
        ~s|if ($_SERVER['REQUEST_METHOD'] === 'POST') { if (!$_POST['csrf']) die(); updateProfile($_POST['email']); }|,
        ~s|if ($_SERVER['REQUEST_METHOD'] === 'POST') { verifyCsrfToken(); updateProfile($_POST['email']); }|,
        ~s|if ($_SERVER['REQUEST_METHOD'] === 'POST') { $csrf = new CsrfValidator(); updateProfile($_POST['email']); }|
      ]

      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end

    test "does not match non-POST requests", %{pattern: pattern} do
      safe_code = [
        ~s|if ($_SERVER['REQUEST_METHOD'] === 'GET') { showProfile(); }|,
        ~s|if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') { sendHeaders(); }|,
        ~s|$method = $_SERVER['REQUEST_METHOD'];|
      ]

      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end

    test "matches commented code (regex limitation)", %{pattern: pattern} do
      # Regex cannot detect comments - this is a known limitation
      code = ~s|// if ($_SERVER['REQUEST_METHOD'] === 'POST') { }|

      assert Regex.match?(pattern.regex, code),
             "Regex matches commented code (AST needed to exclude)"
    end

    test "matches multi-line POST handlers without CSRF", %{pattern: pattern} do
      vulnerable_code = """
      if ($_SERVER['REQUEST_METHOD'] === 'POST') {
          $username = $_POST['username'];
          $email = $_POST['email'];
          updateUser($username, $email);
      }
      """

      assert Regex.match?(pattern.regex, vulnerable_code),
             "Should match multi-line POST handler without CSRF"
    end

    test "does not match multi-line POST handlers with CSRF", %{pattern: pattern} do
      safe_code = """
      if ($_SERVER['REQUEST_METHOD'] === 'POST') {
          if (!verifyCSRFToken($_POST['csrf_token'])) {
              die('Invalid CSRF token');
          }
          updateUser($_POST['username'], $_POST['email']);
      }
      """

      refute Regex.match?(pattern.regex, safe_code),
             "Should not match POST handler with CSRF check"
    end
  end

  describe "test_cases/0" do
    test "all positive cases match" do
      pattern = MissingCsrfToken.pattern()
      test_cases = MissingCsrfToken.test_cases()

      for test_case <- test_cases.positive do
        assert Regex.match?(pattern.regex, test_case.code),
               "Failed to match positive case: #{test_case.description}"
      end
    end

    test "negative cases are documented correctly" do
      test_cases = MissingCsrfToken.test_cases()

      assert length(test_cases.negative) > 0

      for test_case <- test_cases.negative do
        assert Map.has_key?(test_case, :code)
        assert Map.has_key?(test_case, :description)
      end
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = MissingCsrfToken.ast_enhancement()

      assert enhancement.min_confidence >= 0.7
      assert length(enhancement.ast_rules) >= 3

      csrf_rule = Enum.find(enhancement.ast_rules, &(&1.type == "csrf_validation"))
      assert csrf_rule
      assert "csrf" in csrf_rule.validation_patterns

      state_rule = Enum.find(enhancement.ast_rules, &(&1.type == "state_changing_operations"))
      assert state_rule
      assert "update" in state_rule.operation_patterns
    end
  end

  describe "pattern metadata" do
    test "has proper OWASP reference" do
      pattern = MissingCsrfToken.pattern()
      assert pattern.owasp_category == "A01:2021"
    end

    test "has educational content" do
      desc = MissingCsrfToken.vulnerability_description()
      assert desc =~ "CSRF"
      assert desc =~ "Cross-Site"
      assert desc =~ "token"
    end

    test "provides safe alternatives" do
      examples = MissingCsrfToken.examples()
      assert Map.has_key?(examples.fixed, "Token validation")
      assert Map.has_key?(examples.fixed, "Double submit cookie")
    end
  end
end
