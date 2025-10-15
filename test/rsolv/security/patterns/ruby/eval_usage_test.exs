defmodule Rsolv.Security.Patterns.Ruby.EvalUsageTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Ruby.EvalUsage
  alias Rsolv.Security.Pattern

  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = EvalUsage.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "ruby-eval-usage"
      assert pattern.name == "Dangerous Eval Usage"
      assert pattern.severity == :critical
      assert pattern.type == :code_injection
      assert pattern.languages == ["ruby"]
    end

    test "includes CWE and OWASP references" do
      pattern = EvalUsage.pattern()

      assert pattern.cwe_id == "CWE-94"
      assert pattern.owasp_category == "A03:2021"
    end

    test "has multiple regex patterns" do
      pattern = EvalUsage.pattern()

      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 4
    end
  end

  describe "regex matching" do
    setup do
      pattern = EvalUsage.pattern()
      {:ok, pattern: pattern}
    end

    test "matches eval with user input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|eval(params[:code])|,
        ~S|eval user_input|,
        ~S|eval(request.body)|,
        ~S|eval(user_data)|,
        ~S|eval("#{user_input}")|,
        ~S|eval params[:script]|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches instance_eval with user input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|obj.instance_eval(params[:code])|,
        ~S|instance_eval(user_input)|,
        ~S|self.instance_eval(user_data)|,
        ~S|instance_eval user_script|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches class_eval and module_eval with user input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|User.class_eval(params[:method])|,
        ~S|class_eval(user_input)|,
        ~S|MyModule.module_eval(params[:code])|,
        ~S|module_eval user_script|,
        ~S|SomeClass.class_eval(user_data)|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches send with params", %{pattern: pattern} do
      vulnerable_code = [
        ~S|obj.send(params[:method])|,
        ~S|send(params[:action])|,
        ~S|user.send(user_input)|,
        ~S|object.send(request.params[:method])|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches const_get with user input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|Object.const_get(params[:class])|,
        ~S|const_get(user_input)|,
        ~S|Module.const_get(params[:module])|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "does not match safe eval patterns", %{pattern: pattern} do
      safe_code = [
        # Static string
        ~S|eval("puts 'hello world'")|,
        # Block syntax
        ~S|instance_eval { @name = 'safe' }|,
        # Block with do..end
        ~S|class_eval do; attr_reader :id; end|,
        # Symbol instead of dynamic input
        ~S|send(:valid_method)|,
        # Static string
        ~S|const_get("SAFE_CONSTANT")|,
        # Different method
        ~S|evaluate_something(params[:data])|,
        # Variable assignment
        ~S|evaluation = params[:score]|
      ]

      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should not match: #{code}"
      end
    end

    test "documents regex limitations for comment detection" do
      # NOTE: This pattern has a known limitation - it will match commented-out code
      # This is acceptable because AST enhancement will filter out comments in practice
      pattern = EvalUsage.pattern()

      commented_code = [
        ~S|# eval(params[:code]) # Commented out|
      ]

      for code <- commented_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Regex limitation: Will match commented code: #{code}"
      end
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = EvalUsage.vulnerability_metadata()

      assert metadata.description =~ "eval"
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 5
      assert length(metadata.real_world_impact) >= 3
      assert length(metadata.cve_examples) >= 2
    end

    test "includes CVE examples from research" do
      metadata = EvalUsage.vulnerability_metadata()

      cve_ids = Enum.map(metadata.cve_examples, & &1.id)
      assert Enum.any?(cve_ids, &String.contains?(&1, "CVE-"))
    end

    test "includes proper references" do
      metadata = EvalUsage.vulnerability_metadata()

      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = EvalUsage.ast_enhancement()

      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)

      assert enhancement.min_confidence >= 0.8
    end

    test "includes eval-specific AST rules" do
      enhancement = EvalUsage.ast_enhancement()

      assert enhancement.ast_rules.node_type == "CallExpression"
      assert "eval" in enhancement.ast_rules.method_names
      assert "instance_eval" in enhancement.ast_rules.method_names
    end

    test "has user input detection" do
      enhancement = EvalUsage.ast_enhancement()

      assert enhancement.ast_rules.user_input_analysis.check_params
      assert "params" in enhancement.ast_rules.user_input_analysis.input_sources
    end
  end
end
