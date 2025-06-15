defmodule RsolvApi.Security.Patterns.Php.UnsafeDeserializationTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Php.UnsafeDeserialization
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = UnsafeDeserialization.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "php-unsafe-deserialization"
      assert pattern.name == "Unsafe Deserialization"
      assert pattern.severity == :critical
      assert pattern.type == :deserialization
      assert pattern.languages == ["php"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = UnsafeDeserialization.pattern()
      
      assert pattern.cwe_id == "CWE-502"
      assert pattern.owasp_category == "A08:2021"
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = UnsafeDeserialization.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches unserialize with user input sources", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$data = unserialize($_COOKIE['data']);|,
        ~S|$obj = unserialize($_POST['object']);|,
        ~S|$result = unserialize($_GET['payload']);|,
        ~S|$user_data = unserialize($_REQUEST['info']);|,
        ~S|unserialize($_COOKIE['session']);|,
        ~S|$config = unserialize($_POST['config']);|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches unserialize with various spacing", %{pattern: pattern} do
      vulnerable_code = [
        ~S|unserialize( $_POST['data'] );|,
        ~S|unserialize(  $_GET['obj']  );|,
        ~S|unserialize($_COOKIE['info']);|,
        ~S|$result=unserialize($_REQUEST['data']);|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe deserialization", %{pattern: pattern} do
      safe_code = [
        ~S|$data = json_decode($_COOKIE['data'], true);|,
        ~S|$obj = unserialize($safe_data);|,
        ~S|$config = unserialize($internal_config);|,
        ~S|$result = unserialize($validated_input);|,
        ~S|$obj = unserialize($data, ['allowed_classes' => ['MyClass']]);|
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end
    
    test "matches real-world vulnerable patterns", %{pattern: pattern} do
      vulnerable_code = [
        ~S|if (isset($_COOKIE['user_prefs'])) { $prefs = unserialize($_COOKIE['user_prefs']); }|,
        ~S|$session_data = unserialize($_POST['session']);|,
        ~S|$cache = unserialize($_GET['cache_data']);|,
        ~S|$object = unserialize($_REQUEST['obj']);|,
        ~S|return unserialize($_COOKIE['state']);|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
  end
  
  describe "test_cases/0" do
    test "all positive cases match" do
      pattern = UnsafeDeserialization.pattern()
      test_cases = UnsafeDeserialization.test_cases()
      
      for test_case <- test_cases.positive do
        assert Regex.match?(pattern.regex, test_case.code),
               "Failed to match positive case: #{test_case.description}"
      end
    end
    
    test "negative cases are documented correctly" do
      test_cases = UnsafeDeserialization.test_cases()
      
      assert length(test_cases.negative) > 0
      
      for test_case <- test_cases.negative do
        assert Map.has_key?(test_case, :code)
        assert Map.has_key?(test_case, :description)
      end
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = UnsafeDeserialization.ast_enhancement()
      
      assert enhancement.min_confidence >= 0.7
      assert length(enhancement.rules) >= 3
      
      insecure_functions_rule = Enum.find(enhancement.rules, &(&1.type == "insecure_functions"))
      assert insecure_functions_rule
      assert "unserialize" in insecure_functions_rule.functions
      
      secure_alternatives_rule = Enum.find(enhancement.rules, &(&1.type == "secure_alternatives"))
      assert secure_alternatives_rule
      assert "json_decode" in secure_alternatives_rule.functions
    end
  end
  
  describe "pattern metadata" do
    test "has proper OWASP reference" do
      pattern = UnsafeDeserialization.pattern()
      assert pattern.owasp_category == "A08:2021"
    end
    
    test "has educational content" do
      desc = UnsafeDeserialization.vulnerability_description()
      assert desc =~ "deserialization"
      assert desc =~ "object injection"
      assert desc =~ "remote code execution"
    end
    
    test "provides safe alternatives" do
      examples = UnsafeDeserialization.examples()
      assert Map.has_key?(examples.fixed, "Using JSON instead")
      assert Map.has_key?(examples.fixed, "Safe unserialize with allowed_classes")
    end
  end
end