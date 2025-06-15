defmodule RsolvApi.Security.Patterns.Php.RegisterGlobalsTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Php.RegisterGlobals
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = RegisterGlobals.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "php-register-globals"
      assert pattern.name == "Register Globals Dependency"
      assert pattern.severity == :medium
      assert pattern.type == :input_validation
      assert pattern.languages == ["php"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = RegisterGlobals.pattern()
      
      assert pattern.cwe_id == "CWE-473"
      assert pattern.owasp_category == "A04:2021"
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = RegisterGlobals.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches uninitialized security variables", %{pattern: pattern} do
      vulnerable_code = [
        ~S|if ($authenticated) { show_content(); }|,
        ~S|if ($admin) { admin_panel(); }|,
        ~S|if ($user_id) { echo "Welcome user $user_id"; }|,
        ~S|if ($logged_in) { display_profile(); }|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches with various whitespace", %{pattern: pattern} do
      vulnerable_code = [
        ~S|if($authenticated){|,
        ~S|if ( $admin ) {|,
        ~S|if( $user_id ){|,
        ~S|if(  $logged_in  ) {|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches nested conditions", %{pattern: pattern} do
      vulnerable_code = [
        "if ($authenticated && $user_id) {",
        "if ($admin || $user_id) {",
        "if (!$logged_in) { redirect('/login'); }"
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe operations", %{pattern: pattern} do
      safe_code = [
        ~S|if ($_SESSION['authenticated']) { show_content(); }|,
        ~S|if ($_POST['is_admin']) { // Don't trust this! }|,
        ~S|if (defined('AUTHENTICATED')) {|,
        ~S|if ($this->authenticated) {|
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end
    
    test "matches initialized variables (requires AST to exclude)", %{pattern: pattern} do
      # Regex cannot detect initialization on same line
      # This is a known limitation that requires AST analysis
      code = ~S|$authenticated = false; if ($authenticated) {|
      
      assert Regex.match?(pattern.regex, code),
             "Regex matches initialized variables (AST needed to exclude)"
    end
    
    test "matches real-world vulnerable patterns", %{pattern: pattern} do
      vulnerable_code = [
        ~S|if ($admin_mode) { include('admin/config.php'); }|,
        ~S|if ($privileged) { $user->grant_access(); }|,
        ~S|if ($bypass_auth) { $_SESSION['user'] = 'admin'; }|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
  end
  
  describe "test_cases/0" do
    test "all positive cases match" do
      pattern = RegisterGlobals.pattern()
      test_cases = RegisterGlobals.test_cases()
      
      for test_case <- test_cases.positive do
        assert Regex.match?(pattern.regex, test_case.code),
               "Failed to match positive case: #{test_case.description}"
      end
    end
    
    test "negative cases are documented correctly" do
      test_cases = RegisterGlobals.test_cases()
      
      assert length(test_cases.negative) > 0
      
      for test_case <- test_cases.negative do
        assert Map.has_key?(test_case, :code)
        assert Map.has_key?(test_case, :description)
      end
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = RegisterGlobals.ast_enhancement()
      
      assert enhancement.min_confidence >= 0.6
      assert length(enhancement.rules) >= 3
      
      variable_rule = Enum.find(enhancement.rules, &(&1.type == "variable_analysis"))
      assert variable_rule
      assert "authenticated" in variable_rule.suspicious_variables
      assert "admin" in variable_rule.suspicious_variables
    end
  end
  
  describe "pattern metadata" do
    test "has proper OWASP reference" do
      pattern = RegisterGlobals.pattern()
      assert pattern.owasp_category == "A04:2021"
    end
    
    test "has educational content" do
      desc = RegisterGlobals.vulnerability_description()
      assert desc =~ "register_globals"
      assert desc =~ "variable"
      assert desc =~ "initialization"
    end
    
    test "provides safe alternatives" do
      examples = RegisterGlobals.examples()
      assert Map.has_key?(examples.fixed, "Explicit initialization")
      assert Map.has_key?(examples.fixed, "Use superglobals")
    end
  end
end