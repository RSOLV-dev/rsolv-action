defmodule Rsolv.Security.Patterns.Python.UnsafeEvalTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Python.UnsafeEval
  alias Rsolv.Security.Pattern

  describe "pattern structure" do
    test "returns correct pattern structure with all required fields" do
      pattern = UnsafeEval.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "python-unsafe-eval"
      assert pattern.name == "Code Injection via eval()"
      assert pattern.type == :rce
      assert pattern.severity == :critical
      assert pattern.languages == ["python"]
      assert pattern.cwe_id == "CWE-95"
      assert pattern.owasp_category == "A03:2021"
      assert is_binary(pattern.recommendation)
      assert is_map(pattern.test_cases)
    end
  end

  describe "vulnerability detection" do
    test "detects eval with various inputs" do
      pattern = UnsafeEval.pattern()

      vulnerable_code = [
        ~S|result = eval(user_input)|,
        ~S|eval(request.data)|,
        ~S|value = eval(request.args.get('expression'))|,
        ~S|computed = eval(f"2 + {user_number}")|,
        ~S|eval('__import__("os").system("id")')|
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match vulnerable code: #{code}"
      end
    end

    test "detects eval in different contexts" do
      pattern = UnsafeEval.pattern()

      vulnerable_code = [
        ~S|if condition: eval(data)|,
        ~S|return eval(expression)|,
        ~S|dangerous = eval(user_provided_code)|,
        ~S|result = eval(input("Enter expression: "))|
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match vulnerable code: #{code}"
      end
    end

    test "detects eval with complex expressions" do
      pattern = UnsafeEval.pattern()

      vulnerable_code = [
        ~S|eval("2 + 2 + " + user_input)|,
        ~S|eval(base64.b64decode(encoded_input))|,
        ~S|eval(data.replace("'", '"'))|,
        ~S|output = eval(compile(code, 'string', 'eval'))|
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match vulnerable code: #{code}"
      end
    end

    test "detects eval in comments for AST filtering" do
      pattern = UnsafeEval.pattern()

      # These should match the regex but be filtered by AST enhancement
      comment_code = [
        ~S|# eval() is dangerous - use ast.literal_eval instead|,
        ~S|# Never use eval(user_input)|,
        ~S|""" Don't use eval() with untrusted data """|
      ]

      for code <- comment_code do
        assert Regex.match?(pattern.regex, code),
               "Should match eval in comments for AST filtering: #{code}"
      end
    end

    test "ignores safe alternatives" do
      pattern = UnsafeEval.pattern()

      safe_code = [
        ~S|result = ast.literal_eval(user_input)|,
        ~S|value = int(request.args.get('number', 0))|,
        ~S|computed = 2 + int(user_number)|,
        ~S|evaluate_expression(data)  # custom safe evaluator|,
        ~S|evaluation = safe_evaluate(expression)|
      ]

      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should NOT match safe code: #{code}"
      end
    end
  end

  describe "vulnerability metadata" do
    test "provides comprehensive metadata" do
      metadata = UnsafeEval.vulnerability_metadata()

      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert is_list(metadata.references)
      assert is_list(metadata.attack_vectors)
      assert is_list(metadata.real_world_impact)
      assert is_list(metadata.safe_alternatives)
      assert is_list(metadata.cve_examples)
      assert length(metadata.cve_examples) >= 3
    end
  end

  describe "AST enhancement" do
    test "returns correct AST enhancement structure" do
      enhancement = UnsafeEval.ast_enhancement()

      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)

      assert enhancement.ast_rules.node_type == "Call"
      assert is_number(enhancement.min_confidence)
    end

    test "AST rules identify eval usage" do
      enhancement = UnsafeEval.ast_enhancement()

      assert is_list(enhancement.ast_rules.function_names)
      assert "eval" in enhancement.ast_rules.function_names
    end

    test "context rules exclude test files" do
      enhancement = UnsafeEval.ast_enhancement()

      assert is_list(enhancement.context_rules.exclude_paths)
      assert ~r/test/ in enhancement.context_rules.exclude_paths
    end

    test "confidence scoring adjusts for context" do
      enhancement = UnsafeEval.ast_enhancement()
      adjustments = enhancement.confidence_rules.adjustments

      assert adjustments["user_controlled_input"] > 0
      assert adjustments["hardcoded_string"] < 0
      assert adjustments["test_code"] < 0
    end
  end

  describe "file applicability" do
    test "applies to Python files" do
      assert UnsafeEval.applies_to_file?("script.py", nil)
      assert UnsafeEval.applies_to_file?("module.pyw", nil)
      assert UnsafeEval.applies_to_file?("app.py", nil)

      refute UnsafeEval.applies_to_file?("script.js", nil)
      refute UnsafeEval.applies_to_file?("config.json", nil)
    end
  end
end
