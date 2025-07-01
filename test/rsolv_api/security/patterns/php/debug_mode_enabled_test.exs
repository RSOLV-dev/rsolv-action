defmodule RsolvApi.Security.Patterns.Php.DebugModeEnabledTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Php.DebugModeEnabled
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = DebugModeEnabled.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "php-debug-mode-enabled"
      assert pattern.name == "Debug Mode Enabled"
      assert pattern.severity == :medium
      assert pattern.type == :information_disclosure
      assert pattern.languages == ["php"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = DebugModeEnabled.pattern()
      
      assert pattern.cwe_id == "CWE-489"
      assert pattern.owasp_category == "A05:2021"
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = DebugModeEnabled.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches display_errors enabled", %{pattern: pattern} do
      vulnerable_code = [
        ~s|ini_set('display_errors', 1);|,
        ~s|ini_set('display_errors', '1');|,
        ~s|ini_set("display_errors", 1);|,
        ~s|ini_set('display_errors', true);|,
        ~s|ini_set('display_errors', 'on');|,
        ~s|ini_set('display_errors', 'On');|,
        ~s|ini_set('display_errors', 'ON');|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches various ini_set syntax", %{pattern: pattern} do
      vulnerable_code = [
        ~s|ini_set( 'display_errors', 1 );|,
        ~s|ini_set('display_errors',1);|,
        ~s|ini_set ( "display_errors" , 1 ) ;|,
        ~s|@ini_set('display_errors', 1);|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe configurations", %{pattern: pattern} do
      safe_code = [
        ~s|ini_set('display_errors', 0);|,
        ~s|ini_set('display_errors', '0');|,
        ~s|ini_set('display_errors', false);|,
        ~s|ini_set('display_errors', 'off');|,
        ~s|ini_set('display_errors', 'Off');|,
        ~s|ini_set('log_errors', 1);|,
        ~s|error_reporting(0);|
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end
    
    test "matches error_reporting with all errors", %{pattern: pattern} do
      vulnerable_code = [
        ~s|error_reporting(E_ALL);|,
        ~s|error_reporting( E_ALL );|,
        ~s{error_reporting(E_ALL | E_STRICT);}
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches commented code (regex limitation)", %{pattern: pattern} do
      # Regex cannot detect comments - this is a known limitation
      code = ~s|// ini_set('display_errors', 1);|
      
      assert Regex.match?(pattern.regex, code),
             "Regex matches commented code (AST needed to exclude)"
    end
  end
  
  describe "test_cases/0" do
    test "all positive cases match" do
      pattern = DebugModeEnabled.pattern()
      test_cases = DebugModeEnabled.test_cases()
      
      for test_case <- test_cases.positive do
        assert Regex.match?(pattern.regex, test_case.code),
               "Failed to match positive case: #{test_case.description}"
      end
    end
    
    test "negative cases are documented correctly" do
      test_cases = DebugModeEnabled.test_cases()
      
      assert length(test_cases.negative) > 0
      
      for test_case <- test_cases.negative do
        assert Map.has_key?(test_case, :code)
        assert Map.has_key?(test_case, :description)
      end
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = DebugModeEnabled.ast_enhancement()
      
      assert enhancement.min_confidence >= 0.7
      assert length(enhancement.ast_rules) >= 3
      
      debug_rule = Enum.find(enhancement.ast_rules, &(&1.type == "debug_settings"))
      assert debug_rule
      assert "display_errors" in debug_rule.dangerous_settings
      
      prod_rule = Enum.find(enhancement.ast_rules, &(&1.type == "production_indicators"))
      assert prod_rule
      assert "production" in prod_rule.production_checks
    end
  end
  
  describe "pattern metadata" do
    test "has proper OWASP reference" do
      pattern = DebugModeEnabled.pattern()
      assert pattern.owasp_category == "A05:2021"
    end
    
    test "has educational content" do
      desc = DebugModeEnabled.vulnerability_description()
      assert desc =~ "debug"
      assert desc =~ "information"
      assert desc =~ "production"
    end
    
    test "provides safe alternatives" do
      examples = DebugModeEnabled.examples()
      assert Map.has_key?(examples.fixed, "Production configuration")
      assert Map.has_key?(examples.fixed, "Environment-based config")
    end
  end
end