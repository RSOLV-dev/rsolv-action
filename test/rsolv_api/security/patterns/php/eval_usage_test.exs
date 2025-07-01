defmodule RsolvApi.Security.Patterns.Php.EvalUsageTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Php.EvalUsage
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = EvalUsage.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "php-eval-usage"
      assert pattern.name == "Code Injection via eval()"
      assert pattern.severity == :critical
      assert pattern.type == :rce
      assert pattern.languages == ["php"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = EvalUsage.pattern()
      
      assert pattern.cwe_id == "CWE-95"
      assert pattern.owasp_category == "A03:2021"
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = EvalUsage.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches eval with direct user input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|eval($_POST['code']);|,
        ~S|eval($_GET['script']);|,
        ~S|eval($_REQUEST['command']);|,
        ~S|eval($_COOKIE['payload']);|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches eval with string concatenation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|eval("return " . $_GET['expression'] . ";");|,
        ~S|eval("$result = " . $_POST['calc'] . ";");|,
        ~S|eval($_REQUEST['func'] . "();");|,
        ~S|eval("echo " . $_COOKIE['output'] . ";");|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "does not match eval with variable assignment (requires AST)", %{pattern: pattern} do
      # These patterns require data flow analysis via AST enhancement
      # Simple regex cannot track variable assignment to usage
      vulnerable_code = [
        ~S|$code = $_POST['code']; eval($code);|,
        ~S|$script = $_GET['script']; eval($script);|,
        ~S|$cmd = $_REQUEST['cmd']; eval($cmd);|
      ]
      
      for code <- vulnerable_code do
        refute Regex.match?(pattern.regex, code),
               "Regex alone cannot detect data flow: #{code}"
      end
    end
    
    test "matches various eval syntax variations", %{pattern: pattern} do
      vulnerable_code = [
        ~S|eval($_POST["code"]);|,
        ~S|eval($_GET["script"]);|,
        ~S|eval( $_POST['code'] );|,
        ~S|eval($_REQUEST['cmd'] . ';');|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches eval with obfuscated input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|eval(base64_decode($_POST['encoded']));|,
        ~S|eval(str_rot13($_GET['obfuscated']));|,
        ~S|eval(gzinflate($_COOKIE['compressed']));|,
        ~S|eval(hex2bin($_REQUEST['hex']));|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe operations", %{pattern: pattern} do
      safe_code = [
        ~S|eval('return 42;');|,
        ~S|eval($safe_static_code);|,
        ~S|evaluate($_POST['expression']);|,
        ~S|echo "eval is dangerous with $_POST[input]";|,
        ~S|$reflection->eval('safe code');|
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end
    
    test "matches commented eval (requires AST to exclude)", %{pattern: pattern} do
      # Comment detection requires AST analysis
      # Simple regex will match this as a false positive
      commented_code = ~S|// eval($_POST['code']);|
      
      assert Regex.match?(pattern.regex, commented_code),
             "Regex matches commented code (AST needed to exclude)"
    end
    
    test "matches real-world vulnerable patterns", %{pattern: pattern} do
      vulnerable_code = [
        ~S|eval("\$template = \"" . $_POST['template'] . "\";");|,
        ~S|eval("define('" . $_GET['constant'] . "', true);");|,
        ~S|eval($_REQUEST['php_code'] . " return true;");|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
  end
  
  describe "test_cases/0" do
    test "all positive cases match" do
      pattern = EvalUsage.pattern()
      test_cases = EvalUsage.test_cases()
      
      for test_case <- test_cases.positive do
        assert Regex.match?(pattern.regex, test_case.code),
               "Failed to match positive case: #{test_case.description}"
      end
    end
    
    test "negative cases are documented correctly" do
      test_cases = EvalUsage.test_cases()
      
      assert length(test_cases.negative) > 0
      
      for test_case <- test_cases.negative do
        assert Map.has_key?(test_case, :code)
        assert Map.has_key?(test_case, :description)
      end
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = EvalUsage.ast_enhancement()
      
      assert enhancement.min_confidence >= 0.8
      assert length(enhancement.ast_rules) >= 3
      
      eval_functions_rule = Enum.find(enhancement.ast_rules, &(&1.type == "eval_functions"))
      assert eval_functions_rule
      assert "eval" in eval_functions_rule.functions
      assert "assert" in eval_functions_rule.functions
      
      user_input_rule = Enum.find(enhancement.ast_rules, &(&1.type == "user_input_analysis"))
      assert user_input_rule
      assert "$_GET" in user_input_rule.dangerous_sources
      assert "$_POST" in user_input_rule.dangerous_sources
    end
  end
  
  describe "pattern metadata" do
    test "has proper OWASP reference" do
      pattern = EvalUsage.pattern()
      assert pattern.owasp_category == "A03:2021"
    end
    
    test "has educational content" do
      desc = EvalUsage.vulnerability_description()
      assert desc =~ "eval"
      assert String.downcase(desc) =~ "code injection"
      assert desc =~ "remote code execution"
    end
    
    test "provides safe alternatives" do
      examples = EvalUsage.examples()
      assert Map.has_key?(examples.fixed, "Specific operations")
      assert Map.has_key?(examples.fixed, "Safe alternatives")
    end
  end
end