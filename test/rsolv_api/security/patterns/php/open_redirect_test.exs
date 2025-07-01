defmodule RsolvApi.Security.Patterns.Php.OpenRedirectTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Php.OpenRedirect
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = OpenRedirect.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "php-open-redirect"
      assert pattern.name == "Open Redirect"
      assert pattern.severity == :medium
      assert pattern.type == :open_redirect
      assert pattern.languages == ["php"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = OpenRedirect.pattern()
      
      assert pattern.cwe_id == "CWE-601"
      assert pattern.owasp_category == "A01:2021"
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = OpenRedirect.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches header redirects with user input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|header("Location: " . $_GET['url']);|,
        ~S|header('Location: ' . $_POST['redirect']);|,
        ~S|header("Location: " . $_REQUEST['next']);|,
        ~S|header('Location: ' . $_COOKIE['return_url']);|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches various header syntax", %{pattern: pattern} do
      vulnerable_code = [
        ~S|header( "Location: " . $_GET['url'] );|,
        ~S|header("Location:".$_POST['url']);|,
        ~S|header("location: " . $_GET['redirect']);|,
        ~S|header('LOCATION: ' . $_REQUEST['url']);|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe operations", %{pattern: pattern} do
      safe_code = [
        ~S|header("Location: /home");|,
        ~S|header("Location: " . $safe_url);|,
        ~S|$redirect = $_GET['url'];|,
        ~S|header("Content-Type: text/html");|
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end
    
    test "matches commented redirects (requires AST to exclude)", %{pattern: pattern} do
      # Regex cannot detect comments
      # This is a known limitation that requires AST analysis
      code = ~S|// header("Location: " . $_GET['url']);|
      
      assert Regex.match?(pattern.regex, code),
             "Regex matches commented code (AST needed to exclude)"
    end
    
    test "matches wp_redirect with user input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|wp_redirect($_GET['redirect_to']);|,
        ~S|wp_redirect($_POST['url']);|,
        ~S|wp_redirect($_REQUEST['returnto']);|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches real-world vulnerable patterns", %{pattern: pattern} do
      vulnerable_code = [
        ~S|header("Location: " . $_GET['url'] . "&verified=1");|,
        ~S|header("Location: https://" . $_GET['domain'] . "/login");|,
        ~S|wp_redirect($_GET['redirect_to'] ?: '/home');|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
  end
  
  describe "test_cases/0" do
    test "all positive cases match" do
      pattern = OpenRedirect.pattern()
      test_cases = OpenRedirect.test_cases()
      
      for test_case <- test_cases.positive do
        assert Regex.match?(pattern.regex, test_case.code),
               "Failed to match positive case: #{test_case.description}"
      end
    end
    
    test "negative cases are documented correctly" do
      test_cases = OpenRedirect.test_cases()
      
      assert length(test_cases.negative) > 0
      
      for test_case <- test_cases.negative do
        assert Map.has_key?(test_case, :code)
        assert Map.has_key?(test_case, :description)
      end
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = OpenRedirect.ast_enhancement()
      
      assert enhancement.min_confidence >= 0.7
      assert length(enhancement.ast_rules) >= 3
      
      redirect_rule = Enum.find(enhancement.ast_rules, &(&1.type == "redirect_functions"))
      assert redirect_rule
      assert "header" in redirect_rule.functions
      
      user_input_rule = Enum.find(enhancement.ast_rules, &(&1.type == "user_input_sources"))
      assert user_input_rule
      assert "$_GET" in user_input_rule.dangerous_sources
    end
  end
  
  describe "pattern metadata" do
    test "has proper OWASP reference" do
      pattern = OpenRedirect.pattern()
      assert pattern.owasp_category == "A01:2021"
    end
    
    test "has educational content" do
      desc = OpenRedirect.vulnerability_description()
      assert desc =~ "redirect"
      assert desc =~ "phishing"
      assert desc =~ "validation"
    end
    
    test "provides safe alternatives" do
      examples = OpenRedirect.examples()
      assert Map.has_key?(examples.fixed, "Allowlist validation")
      assert Map.has_key?(examples.fixed, "Relative URL check")
    end
  end
end