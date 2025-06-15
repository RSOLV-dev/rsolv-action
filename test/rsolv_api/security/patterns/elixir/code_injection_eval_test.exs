defmodule RsolvApi.Security.Patterns.Elixir.CodeInjectionEvalTest do
  use ExUnit.Case, async: true

  alias RsolvApi.Security.Patterns.Elixir.CodeInjectionEval
  alias RsolvApi.Security.Pattern

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = CodeInjectionEval.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "elixir-code-injection-eval"
      assert pattern.name == "Code Injection via eval"
      assert pattern.type == :code_injection
      assert pattern.severity == :critical
      assert pattern.languages == ["elixir"]
      assert pattern.cwe_id == "CWE-94"
      assert pattern.owasp_category == "A03:2021"
      assert pattern.default_tier == :public
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "pattern has comprehensive test cases" do
      pattern = CodeInjectionEval.pattern()
      
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
      assert length(pattern.test_cases.vulnerable) >= 3
      assert length(pattern.test_cases.safe) >= 3
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = CodeInjectionEval.vulnerability_metadata()
      
      assert is_map(metadata)
      assert Map.has_key?(metadata, :description)
      assert Map.has_key?(metadata, :references)
      assert Map.has_key?(metadata, :attack_vectors)
      assert Map.has_key?(metadata, :real_world_impact)
      assert Map.has_key?(metadata, :cve_examples)
      assert Map.has_key?(metadata, :safe_alternatives)
      
      assert String.length(metadata.description) > 100
      assert length(metadata.references) >= 3
      assert length(metadata.attack_vectors) >= 3
      assert length(metadata.cve_examples) >= 1
    end

    test "includes code execution information" do
      metadata = CodeInjectionEval.vulnerability_metadata()
      
      # Should mention eval or code execution
      assert String.contains?(metadata.description, "eval") or
             String.contains?(metadata.description, "code execution")
      
      # Should mention pattern matching as safe alternative
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "pattern matching"))
    end

    test "references include CWE-94 and OWASP A03:2021" do
      metadata = CodeInjectionEval.vulnerability_metadata()
      
      cwe_ref = Enum.find(metadata.references, &(&1.type == :cwe))
      assert cwe_ref.id == "CWE-94"
      
      owasp_ref = Enum.find(metadata.references, &(&1.type == :owasp))
      assert owasp_ref.id == "A03:2021"
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper AST enhancement structure" do
      enhancement = CodeInjectionEval.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence == 0.8
    end

    test "AST rules check for eval functions" do
      enhancement = CodeInjectionEval.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert Map.has_key?(enhancement.ast_rules, :eval_analysis)
      assert enhancement.ast_rules.eval_analysis.check_eval_functions == true
      assert "Code.eval_string" in enhancement.ast_rules.eval_analysis.dangerous_functions
    end

    test "context rules identify user input sources" do
      enhancement = CodeInjectionEval.ast_enhancement()
      
      assert Map.has_key?(enhancement.context_rules, :user_input_sources)
      assert "params" in enhancement.context_rules.user_input_sources
      assert "conn.body_params" in enhancement.context_rules.user_input_sources
    end

    test "confidence adjustments for user input" do
      enhancement = CodeInjectionEval.ast_enhancement()
      
      assert enhancement.confidence_rules.base == 0.6
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "has_user_input")
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "uses_compile_time_code")
    end
  end

  describe "vulnerable code detection" do
    test "detects Code.eval_string with user input" do
      pattern = CodeInjectionEval.pattern()
      
      vulnerable_code = ~S|Code.eval_string(params["code"])|
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
      
      vulnerable_code2 = ~S|Code.eval_string(user_input)|
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code2))
    end

    test "detects Code.eval_file usage" do
      pattern = CodeInjectionEval.pattern()
      
      vulnerable_code = ~S|Code.eval_file(file_path)|
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
      
      vulnerable_code2 = ~S|Code.eval_file("scripts/#{script_name}.exs")|
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code2))
    end

    test "detects Code.eval_quoted usage" do
      pattern = CodeInjectionEval.pattern()
      
      vulnerable_code = ~S|Code.eval_quoted(ast)|
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
      
      vulnerable_code2 = ~S|{result, _} = Code.eval_quoted(user_ast)|
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code2))
    end

    test "detects EEx eval functions" do
      pattern = CodeInjectionEval.pattern()
      
      vulnerable_code = ~S|EEx.eval_string(template, assigns)|
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
      
      vulnerable_code2 = ~S|EEx.eval_file(template_path)|
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code2))
    end

    test "detects pipe operations to eval" do
      pattern = CodeInjectionEval.pattern()
      
      vulnerable_code = "user_code |> Code.eval_string()"
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end
  end

  describe "safe code validation" do
    test "does not match compile-time code generation" do
      pattern = CodeInjectionEval.pattern()
      
      # Macro usage is safe
      safe_code = ~S|defmacro generate_functions do
  quote do
    def hello, do: "world"
  end
end|
      refute Enum.any?(pattern.regex, &Regex.match?(&1, safe_code))
    end

    test "does not match pattern matching" do
      pattern = CodeInjectionEval.pattern()
      
      safe_code = ~S|case command do
  "start" -> start_process()
  "stop" -> stop_process()
  _ -> {:error, :unknown_command}
end|
      refute Enum.any?(pattern.regex, &Regex.match?(&1, safe_code))
    end

    test "does not match AST manipulation without eval" do
      pattern = CodeInjectionEval.pattern()
      
      safe_code = ~S|quote do
  def unquote(name)(), do: unquote(value)
end|
      refute Enum.any?(pattern.regex, &Regex.match?(&1, safe_code))
    end

    test "does not match function references" do
      pattern = CodeInjectionEval.pattern()
      
      safe_code = ~S|apply(Module, :function, args)|
      refute Enum.any?(pattern.regex, &Regex.match?(&1, safe_code))
    end
  end

  describe "enhanced_pattern/0" do
    test "uses ast_enhancement for better detection" do
      enhanced = CodeInjectionEval.enhanced_pattern()
      
      assert enhanced.id == "elixir-code-injection-eval"
      assert Map.has_key?(enhanced, :ast_enhancement)
      assert enhanced.ast_enhancement == CodeInjectionEval.ast_enhancement()
    end
  end
end