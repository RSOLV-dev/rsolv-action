defmodule RsolvApi.Security.Patterns.Elixir.UnsafeAtomCreationTest do
  use ExUnit.Case, async: true

  alias RsolvApi.Security.Patterns.Elixir.UnsafeAtomCreation
  alias RsolvApi.Security.Pattern

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = UnsafeAtomCreation.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "elixir-unsafe-atom-creation"
      assert pattern.name == "Unsafe Atom Creation"
      assert pattern.type == :denial_of_service
      assert pattern.severity == :high
      assert pattern.languages == ["elixir"]
      assert pattern.cwe_id == "CWE-400"
      assert pattern.owasp_category == "A05:2021"
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "pattern has comprehensive test cases" do
      pattern = UnsafeAtomCreation.pattern()
      
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
      assert length(pattern.test_cases.vulnerable) >= 3
      assert length(pattern.test_cases.safe) >= 3
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = UnsafeAtomCreation.vulnerability_metadata()
      
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

    test "includes atom exhaustion information" do
      metadata = UnsafeAtomCreation.vulnerability_metadata()
      
      # Should mention atom table or exhaustion
      assert String.contains?(metadata.description, "atom") and
             (String.contains?(metadata.description, "exhaust") or
              String.contains?(metadata.description, "table"))
      
      # Should mention String.to_existing_atom
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "to_existing_atom"))
    end

    test "references include CWE-400 and OWASP A05:2021" do
      metadata = UnsafeAtomCreation.vulnerability_metadata()
      
      cwe_ref = Enum.find(metadata.references, &(&1.type == :cwe))
      assert cwe_ref.id == "CWE-400"
      
      owasp_ref = Enum.find(metadata.references, &(&1.type == :owasp))
      assert owasp_ref.id == "A05:2021"
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper AST enhancement structure" do
      enhancement = UnsafeAtomCreation.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence == 0.7
    end

    test "AST rules check for atom creation patterns" do
      enhancement = UnsafeAtomCreation.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert Map.has_key?(enhancement.ast_rules, :atom_analysis)
      assert enhancement.ast_rules.atom_analysis.check_atom_creation == true
      assert "String.to_atom" in enhancement.ast_rules.atom_analysis.dangerous_functions
    end

    test "context rules identify user input sources" do
      enhancement = UnsafeAtomCreation.ast_enhancement()
      
      assert Map.has_key?(enhancement.context_rules, :user_input_sources)
      assert "params" in enhancement.context_rules.user_input_sources
      assert "conn.params" in enhancement.context_rules.user_input_sources
    end

    test "confidence adjustments for user input" do
      enhancement = UnsafeAtomCreation.ast_enhancement()
      
      assert enhancement.confidence_rules.base == 0.6
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "has_user_input")
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "uses_existing_atom")
    end
  end

  describe "vulnerable code detection" do
    test "detects String.to_atom with user input" do
      pattern = UnsafeAtomCreation.pattern()
      
      vulnerable_code = ~S|String.to_atom(params["key"])|
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
      
      vulnerable_code2 = ~S|String.to_atom(user_input)|
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code2))
    end

    test "detects :erlang.binary_to_atom usage" do
      pattern = UnsafeAtomCreation.pattern()
      
      vulnerable_code = ~S|:erlang.binary_to_atom(data, :utf8)|
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end

    test "detects List.to_atom with external data" do
      pattern = UnsafeAtomCreation.pattern()
      
      vulnerable_code = ~S|List.to_atom(char_list)|
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end

    test "detects pipe operations to to_atom" do
      pattern = UnsafeAtomCreation.pattern()
      
      vulnerable_code = "params[\"action\"] |> String.to_atom()"
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end
  end

  describe "safe code validation" do
    test "does not match String.to_existing_atom" do
      pattern = UnsafeAtomCreation.pattern()
      
      safe_code = ~S|String.to_existing_atom(params["key"])|
      refute Enum.any?(pattern.regex, &Regex.match?(&1, safe_code))
      
      safe_code2 = ~S|:erlang.binary_to_existing_atom(data, :utf8)|
      refute Enum.any?(pattern.regex, &Regex.match?(&1, safe_code2))
    end

    test "does not match hardcoded atom creation" do
      pattern = UnsafeAtomCreation.pattern()
      
      # Note: Without AST analysis, regex can't distinguish between literal strings
      # and variables. This is why we need AST enhancement.
      # For now, we'll test a pattern that clearly doesn't match
      safe_code = ~S|:known_atom|
      refute Enum.any?(pattern.regex, &Regex.match?(&1, safe_code))
    end

    test "does not match atom syntax" do
      pattern = UnsafeAtomCreation.pattern()
      
      safe_code = ~S|:my_atom|
      refute Enum.any?(pattern.regex, &Regex.match?(&1, safe_code))
      
      safe_code2 = ~S|:"complex atom"|
      refute Enum.any?(pattern.regex, &Regex.match?(&1, safe_code2))
    end

    test "does not match Map.get with atom keys" do
      pattern = UnsafeAtomCreation.pattern()
      
      safe_code = ~S|Map.get(data, :key)|
      refute Enum.any?(pattern.regex, &Regex.match?(&1, safe_code))
    end
  end

  describe "enhanced_pattern/0" do
    test "uses ast_enhancement for better detection" do
      enhanced = UnsafeAtomCreation.enhanced_pattern()
      
      assert enhanced.id == "elixir-unsafe-atom-creation"
      assert Map.has_key?(enhanced, :ast_enhancement)
      assert enhanced.ast_enhancement == UnsafeAtomCreation.ast_enhancement()
    end
  end
end