defmodule RsolvApi.Security.Patterns.Elixir.DeserializationErlangTest do
  use ExUnit.Case, async: true

  alias RsolvApi.Security.Patterns.Elixir.DeserializationErlang
  alias RsolvApi.Security.Pattern

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = DeserializationErlang.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "elixir-deserialization-erlang"
      assert pattern.name == "Unsafe Erlang Term Deserialization"
      assert pattern.type == :deserialization
      assert pattern.severity == :critical
      assert pattern.languages == ["elixir"]
      assert pattern.cwe_id == "CWE-502"
      assert pattern.owasp_category == "A08:2021"
      assert is_list(pattern.regex) or pattern.regex.__struct__ == Regex
    end

    test "pattern has comprehensive test cases" do
      pattern = DeserializationErlang.pattern()
      
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
      assert length(pattern.test_cases.vulnerable) >= 3
      assert length(pattern.test_cases.safe) >= 3
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = DeserializationErlang.vulnerability_metadata()
      
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

    test "includes deserialization information" do
      metadata = DeserializationErlang.vulnerability_metadata()
      
      # Should mention binary_to_term or ETF
      assert String.contains?(metadata.description, "binary_to_term") or
             String.contains?(metadata.description, "ETF")
      
      # Should mention [:safe] option limitations
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "safe")) or
             Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "JSON"))
    end

    test "references include CWE-502 and OWASP A08:2021" do
      metadata = DeserializationErlang.vulnerability_metadata()
      
      cwe_ref = Enum.find(metadata.references, &(&1.type == :cwe))
      assert cwe_ref.id == "CWE-502"
      
      owasp_ref = Enum.find(metadata.references, &(&1.type == :owasp))
      assert owasp_ref.id == "A08:2021"
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper AST enhancement structure" do
      enhancement = DeserializationErlang.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.7
    end

    test "AST rules check for binary_to_term calls" do
      enhancement = DeserializationErlang.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert Map.has_key?(enhancement.ast_rules, :deserialization_analysis)
      assert enhancement.ast_rules.deserialization_analysis.check_binary_to_term == true
    end

    test "context rules identify user input sources" do
      enhancement = DeserializationErlang.ast_enhancement()
      
      assert Map.has_key?(enhancement.context_rules, :user_input_sources)
      assert "params" in enhancement.context_rules.user_input_sources
      assert "conn.body_params" in enhancement.context_rules.user_input_sources
    end

    test "confidence adjustments for safe option" do
      enhancement = DeserializationErlang.ast_enhancement()
      
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "has_user_input")
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "uses_safe_option")
    end
  end

  describe "vulnerable code detection" do
    test "detects direct binary_to_term usage" do
      pattern = DeserializationErlang.pattern()
      
      vulnerable_code = ~S|:erlang.binary_to_term(user_data)|
      assert pattern_matches?(pattern, vulnerable_code)
      
      vulnerable_code2 = ~S|:erlang.binary_to_term(Base.decode64!(encoded))|
      assert pattern_matches?(pattern, vulnerable_code2)
    end

    test "detects unsafe binary_to_term without safe option" do
      pattern = DeserializationErlang.pattern()
      
      vulnerable_code = ~S|data = :erlang.binary_to_term(params["data"])|
      assert pattern_matches?(pattern, vulnerable_code)
      
      vulnerable_code2 = ~S|{result, _} = :erlang.binary_to_term(socket.assigns.data)|
      assert pattern_matches?(pattern, vulnerable_code2)
    end

    test "detects even with safe option (still vulnerable to function execution)" do
      pattern = DeserializationErlang.pattern()
      
      # Even with [:safe], it can still execute functions
      vulnerable_code = ~S|:erlang.binary_to_term(user_data, [:safe])|
      assert pattern_matches?(pattern, vulnerable_code)
    end

    test "detects pipe operations" do
      pattern = DeserializationErlang.pattern()
      
      vulnerable_code = "user_data |> :erlang.binary_to_term()"
      assert pattern_matches?(pattern, vulnerable_code)
      
      vulnerable_code2 = "Base.decode64!(encoded) |> :erlang.binary_to_term([:safe])"
      assert pattern_matches?(pattern, vulnerable_code2)
    end

    test "detects multiline usage" do
      pattern = DeserializationErlang.pattern()
      
      vulnerable_code = """
      decoded = Base.decode64!(encoded_data)
      result = :erlang.binary_to_term(decoded)
      """
      assert pattern_matches?(pattern, vulnerable_code)
    end
  end

  describe "safe code validation" do
    test "does not match term_to_binary (serialization)" do
      pattern = DeserializationErlang.pattern()
      
      safe_code = ~S|:erlang.term_to_binary(data)|
      refute pattern_matches?(pattern, safe_code)
    end

    test "does not match JSON deserialization" do
      pattern = DeserializationErlang.pattern()
      
      safe_code = ~S|Jason.decode!(user_data)|
      refute pattern_matches?(pattern, safe_code)
      
      safe_code2 = ~S|Poison.decode!(json_string)|
      refute pattern_matches?(pattern, safe_code2)
    end

    test "does not match other safe parsing" do
      pattern = DeserializationErlang.pattern()
      
      safe_code = ~S|String.to_integer(user_input)|
      refute pattern_matches?(pattern, safe_code)
    end

    test "does not match comments about binary_to_term" do
      pattern = DeserializationErlang.pattern()
      
      safe_code = ~S|# Never use :erlang.binary_to_term with user input|
      refute pattern_matches?(pattern, safe_code)
    end
  end

  describe "enhanced_pattern/0" do
    test "uses ast_enhancement for better detection" do
      enhanced = DeserializationErlang.enhanced_pattern()
      
      assert enhanced.id == "elixir-deserialization-erlang"
      assert Map.has_key?(enhanced, :ast_enhancement)
      assert enhanced.ast_enhancement == DeserializationErlang.ast_enhancement()
    end
  end

  # Helper function to check if pattern matches
  defp pattern_matches?(pattern, code) do
    case pattern.regex do
      regexes when is_list(regexes) ->
        Enum.any?(regexes, fn regex -> Regex.match?(regex, code) end)
      regex ->
        Regex.match?(regex, code)
    end
  end
end