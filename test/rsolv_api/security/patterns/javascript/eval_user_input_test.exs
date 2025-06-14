defmodule RsolvApi.Security.Patterns.Javascript.EvalUserInputTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Javascript.EvalUserInput
  alias RsolvApi.Security.Pattern
  
  doctest EvalUserInput
  
  describe "EvalUserInput pattern" do
    test "pattern/0 returns correct structure" do
      pattern = EvalUserInput.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-eval-user-input"
      assert pattern.name == "Dangerous eval() with User Input"
      assert pattern.description == "Using eval() with user input can execute arbitrary code"
      assert pattern.type == :rce
      assert pattern.severity == :critical
      assert pattern.languages == ["javascript", "typescript"]
      assert pattern.default_tier == :protected
      assert pattern.cwe_id == "CWE-94"
      assert pattern.owasp_category == "A03:2021"
      assert is_binary(pattern.recommendation)
      assert is_map(pattern.test_cases)
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
    end
    
    test "pattern detects vulnerable eval() usage with user input" do
      pattern = EvalUserInput.pattern()
      
      vulnerable_cases = [
        ~S|eval(userInput)|,
        ~S|eval(req.body.code)|,
        ~S|const result = eval("2 + " + params.number)|,
        ~S|eval(request.params.expression)|,
        ~S|eval(req.query.formula)|,
        ~S|var output = eval(inputData)|,
        ~S|return eval(user.customScript)|,
        ~S|eval("return " + req.body.expression)|,
        ~S|const fn = eval("function() { " + userCode + " }")|,
        ~S|eval(data.computation)|
      ]
      
      for code <- vulnerable_cases do
        assert Regex.match?(pattern.regex, code), 
          "Failed to match vulnerable code: #{code}"
      end
    end
    
    test "pattern does not match safe eval() alternatives" do
      pattern = EvalUserInput.pattern()
      
      safe_cases = [
        ~S|JSON.parse(userInput)|,
        ~S|const fn = new Function("return " + sanitizedExpression)|,
        ~S|const result = calculateSafely(params.number)|,
        ~S|eval("2 + 2")  // static expression|,
        ~S|const math = safeEval(expression, context)|,
        ~S|vm.runInContext(code, sandbox)|,
        ~S|Function("return " + validatedExpression)()|,
        ~S|console.log("eval should be avoided")|,
        ~S|const evalWarning = "Don't use eval()"|
      ]
      
      for code <- safe_cases do
        refute Regex.match?(pattern.regex, code),
          "Incorrectly matched safe code: #{code}"
      end
    end
    
    test "validate_match/1 filters out comments correctly" do
      # Comments should be filtered out
      refute EvalUserInput.validate_match(~S|// Never use eval() with user input|)
      refute EvalUserInput.validate_match(~S|  // eval(userData) is dangerous|)
      refute EvalUserInput.validate_match(~S|const x = 1; // eval(input) bad|)
      refute EvalUserInput.validate_match(~S|/* eval(userInput) in comment */|)
      
      # Real vulnerabilities should pass
      assert EvalUserInput.validate_match(~S|eval(userInput)|)
      assert EvalUserInput.validate_match(~S|const result = eval(req.body.code)|)
      assert EvalUserInput.validate_match(~S|eval("function() { " + userCode + " }")|)
      
      # String literals mentioning eval should be safe
      assert EvalUserInput.validate_match(~S|const warning = "don't use eval()"|)
    end
    
    test "vulnerability_metadata/0 returns comprehensive metadata" do
      metadata = EvalUserInput.vulnerability_metadata()
      
      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert String.length(metadata.description) > 100
      
      # Check references structure
      assert is_list(metadata.references)
      assert length(metadata.references) >= 4
      
      for ref <- metadata.references do
        assert Map.has_key?(ref, :type)
        assert Map.has_key?(ref, :url)
        assert ref.type in [:cwe, :owasp, :nist, :research, :sans, :vendor]
        assert String.starts_with?(ref.url, "http")
      end
      
      # Check attack vectors
      assert is_list(metadata.attack_vectors)
      assert length(metadata.attack_vectors) >= 5
      
      # Check real world impact
      assert is_list(metadata.real_world_impact)
      assert length(metadata.real_world_impact) >= 5
      
      # Check CVE examples
      assert is_list(metadata.cve_examples)
      assert length(metadata.cve_examples) >= 3
      
      for cve <- metadata.cve_examples do
        assert Map.has_key?(cve, :id)
        assert Map.has_key?(cve, :description)
        assert Map.has_key?(cve, :severity)
        assert String.starts_with?(cve.id, "CVE-")
        assert cve.severity in ["low", "medium", "high", "critical"]
      end
      
      # Check safe alternatives
      assert is_list(metadata.safe_alternatives)
      assert length(metadata.safe_alternatives) >= 5
      
      # Check detection notes
      assert is_binary(metadata.detection_notes)
      assert String.length(metadata.detection_notes) > 50
    end
    
    test "applies_to_file?/1 works correctly" do
      # JavaScript and TypeScript files
      assert EvalUserInput.applies_to_file?("test.js")
      assert EvalUserInput.applies_to_file?("app.jsx")
      assert EvalUserInput.applies_to_file?("server.ts")
      assert EvalUserInput.applies_to_file?("component.tsx")
      assert EvalUserInput.applies_to_file?("module.mjs")
      
      # Non-JavaScript files
      refute EvalUserInput.applies_to_file?("test.py")
      refute EvalUserInput.applies_to_file?("app.rb")
      refute EvalUserInput.applies_to_file?("server.php")
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns comprehensive AST enhancement rules" do
      enhancement = EvalUserInput.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.keys(enhancement) == [:ast_rules, :context_rules, :confidence_rules, :min_confidence]
    end
    
    test "AST rules target eval call expressions" do
      enhancement = EvalUserInput.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert enhancement.ast_rules.callee.name == "eval"
      assert enhancement.ast_rules.callee.alternatives == ["Function", "setTimeout", "setInterval"]
      assert enhancement.ast_rules.argument_analysis.first_arg_contains_user_input == true
      assert enhancement.ast_rules.argument_analysis.is_string_type == true
      assert enhancement.ast_rules.argument_analysis.not_static_string == true
    end
    
    test "context rules exclude test files and safe patterns" do
      enhancement = EvalUserInput.ast_enhancement()
      
      assert Enum.any?(enhancement.context_rules.exclude_paths, &(&1 == ~r/test/))
      assert Enum.any?(enhancement.context_rules.exclude_paths, &(&1 == ~r/build/))
      assert enhancement.context_rules.exclude_if_json_parse_only == true
      assert enhancement.context_rules.exclude_if_math_only == true
      assert enhancement.context_rules.exclude_if_sandboxed == true
      assert enhancement.context_rules.exclude_if_generated_code == true
      assert enhancement.context_rules.high_risk_sources == ["req.body", "req.query", "localStorage", "location.search"]
    end
    
    test "confidence rules heavily penalize safe patterns" do
      enhancement = EvalUserInput.ast_enhancement()
      
      assert enhancement.confidence_rules.base == 0.5
      assert enhancement.confidence_rules.adjustments["direct_req_body_to_eval"] == 0.5
      assert enhancement.confidence_rules.adjustments["url_params_to_eval"] == 0.4
      assert enhancement.confidence_rules.adjustments["any_user_input_to_eval"] == 0.3
      assert enhancement.confidence_rules.adjustments["uses_vm2_sandbox"] == -0.8
      assert enhancement.confidence_rules.adjustments["json_parse_pattern"] == -0.7
      assert enhancement.confidence_rules.adjustments["static_math_expression"] == -0.9
      assert enhancement.confidence_rules.adjustments["webpack_generated"] == -1.0
      assert enhancement.min_confidence == 0.8
    end
  end
  
  describe "enhanced_pattern/0" do
    test "returns pattern with AST enhancement from ast_enhancement/0" do
      enhanced = EvalUserInput.enhanced_pattern()
      enhancement = EvalUserInput.ast_enhancement()
      
      # Verify it has all the AST enhancement fields
      assert enhanced.ast_rules == enhancement.ast_rules
      assert enhanced.context_rules == enhancement.context_rules
      assert enhanced.confidence_rules == enhancement.confidence_rules
      assert enhanced.min_confidence == enhancement.min_confidence
      
      # And still has all the pattern fields
      assert enhanced.id == "js-eval-user-input"
      assert enhanced.severity == :critical
    end
  end
end