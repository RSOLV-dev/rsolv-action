defmodule Rsolv.Security.Patterns.Php.SessionFixationTest do
  use ExUnit.Case, async: true
  
  alias Rsolv.Security.Patterns.Php.SessionFixation
  alias Rsolv.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = SessionFixation.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "php-session-fixation"
      assert pattern.name == "Session Fixation"
      assert pattern.severity == :high
      assert pattern.type == :session_management
      assert pattern.languages == ["php"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = SessionFixation.pattern()
      
      assert pattern.cwe_id == "CWE-384"
      assert pattern.owasp_category == "A07:2021"
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = SessionFixation.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches session_id with GET parameter", %{pattern: pattern} do
      vulnerable_code = [
        ~S|session_id($_GET['sid']);|,
        ~S|session_id($_GET['sessionid']);|,
        ~S|session_id($_GET['session']);|,
        ~S|session_id($_GET['PHPSESSID']);|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches session_id with POST parameter", %{pattern: pattern} do
      vulnerable_code = [
        ~S|session_id($_POST['sid']);|,
        ~S|session_id($_POST['sessionid']);|,
        ~S|session_id($_POST['session_token']);|,
        ~S|session_id($_POST['user_session']);|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches session_id with REQUEST parameter", %{pattern: pattern} do
      vulnerable_code = [
        ~S|session_id($_REQUEST['sid']);|,
        ~S|session_id($_REQUEST['session']);|,
        ~S|session_id($_REQUEST['session_id']);|,
        ~S|session_id($_REQUEST['JSESSIONID']);|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches session_id with COOKIE parameter", %{pattern: pattern} do
      vulnerable_code = [
        ~S|session_id($_COOKIE['sid']);|,
        ~S|session_id($_COOKIE['PHPSESSID']);|,
        ~S|session_id($_COOKIE['session_token']);|,
        ~S|session_id($_COOKIE['custom_session']);|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches various spacing and formatting", %{pattern: pattern} do
      vulnerable_code = [
        ~S|session_id( $_GET['sid'] );|,
        ~S|session_id(  $_POST['session']  );|,
        ~S|session_id($_REQUEST['id']);|,
        ~S|session_id( $_COOKIE['token'] );|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe operations", %{pattern: pattern} do
      safe_code = [
        ~S|session_id();|,
        ~S|$session_id = session_id();|,
        ~S|session_regenerate_id(true);|,
        ~S|session_id($generated_id);|,
        ~S|session_start();|,
        ~S|$old_id = session_id();|,
        ~S|echo session_id();|
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end
    
    test "matches real-world vulnerable patterns", %{pattern: pattern} do
      vulnerable_code = [
        ~S|if (isset($_GET['PHPSESSID'])) { session_id($_GET['PHPSESSID']); }|,
        ~S|session_id($_REQUEST['user_session']);|,
        ~S|// Set custom session ID\nsession_id($_COOKIE['session_token']);|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
  end
  
  describe "test_cases/0" do
    test "all positive cases match" do
      pattern = SessionFixation.pattern()
      test_cases = SessionFixation.test_cases()
      
      for test_case <- test_cases.positive do
        assert Regex.match?(pattern.regex, test_case.code),
               "Failed to match positive case: #{test_case.description}"
      end
    end
    
    test "negative cases are documented correctly" do
      test_cases = SessionFixation.test_cases()
      
      assert length(test_cases.negative) > 0
      
      for test_case <- test_cases.negative do
        assert Map.has_key?(test_case, :code)
        assert Map.has_key?(test_case, :description)
      end
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = SessionFixation.ast_enhancement()
      
      assert enhancement.min_confidence >= 0.7
      assert length(enhancement.ast_rules) >= 3
      
      session_functions_rule = Enum.find(enhancement.ast_rules, &(&1.type == "session_functions"))
      assert session_functions_rule
      assert "session_id" in session_functions_rule.functions
      assert "session_start" in session_functions_rule.functions
      
      user_input_rule = Enum.find(enhancement.ast_rules, &(&1.type == "user_input_analysis"))
      assert user_input_rule
      assert "$_GET" in user_input_rule.dangerous_sources
      assert "$_POST" in user_input_rule.dangerous_sources
    end
  end
  
  describe "pattern metadata" do
    test "has proper OWASP reference" do
      pattern = SessionFixation.pattern()
      assert pattern.owasp_category == "A07:2021"
    end
    
    test "has educational content" do
      desc = SessionFixation.vulnerability_description()
      assert desc =~ "Session fixation"
      assert desc =~ "session_regenerate_id"
      assert desc =~ "attacker"
    end
    
    test "provides safe alternatives" do
      examples = SessionFixation.examples()
      assert Map.has_key?(examples.fixed, "Session regeneration")
      assert Map.has_key?(examples.fixed, "Login security")
    end
  end
end