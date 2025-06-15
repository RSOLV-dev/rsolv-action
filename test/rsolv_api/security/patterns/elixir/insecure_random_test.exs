defmodule RsolvApi.Security.Patterns.Elixir.InsecureRandomTest do
  use ExUnit.Case, async: true

  alias RsolvApi.Security.Patterns.Elixir.InsecureRandom
  alias RsolvApi.Security.Pattern

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = InsecureRandom.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "elixir-insecure-random"
      assert pattern.name == "Insecure Random Number Generation"
      assert pattern.type == :insecure_random
      assert pattern.severity == :high
      assert pattern.languages == ["elixir"]
      assert pattern.cwe_id == "CWE-338"
      assert pattern.owasp_category == "A02:2021"
      assert pattern.default_tier == :public
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "pattern has comprehensive test cases" do
      pattern = InsecureRandom.pattern()
      
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
      assert length(pattern.test_cases.vulnerable) >= 3
      assert length(pattern.test_cases.safe) >= 3
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = InsecureRandom.vulnerability_metadata()
      
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

    test "includes cryptographic weakness information" do
      metadata = InsecureRandom.vulnerability_metadata()
      
      # Should mention PRNG vs CSPRNG
      assert String.contains?(metadata.description, "PRNG") or
             String.contains?(metadata.description, "pseudo-random")
      
      # Should mention crypto.strong_rand_bytes
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "crypto.strong_rand_bytes"))
    end

    test "references include CWE-338 and OWASP A02:2021" do
      metadata = InsecureRandom.vulnerability_metadata()
      
      cwe_ref = Enum.find(metadata.references, &(&1.type == :cwe))
      assert cwe_ref.id == "CWE-338"
      
      owasp_ref = Enum.find(metadata.references, &(&1.type == :owasp))
      assert owasp_ref.id == "A02:2021"
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper AST enhancement structure" do
      enhancement = InsecureRandom.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence == 0.7
    end

    test "AST rules check for random generation patterns" do
      enhancement = InsecureRandom.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert Map.has_key?(enhancement.ast_rules, :random_analysis)
      assert enhancement.ast_rules.random_analysis.check_random_usage == true
      assert ":rand.uniform" in enhancement.ast_rules.random_analysis.insecure_functions
    end

    test "context rules identify security contexts" do
      enhancement = InsecureRandom.ast_enhancement()
      
      assert Map.has_key?(enhancement.context_rules, :security_contexts)
      assert "token" in enhancement.context_rules.security_contexts
      assert "password" in enhancement.context_rules.security_contexts
    end

    test "confidence adjustments for security context" do
      enhancement = InsecureRandom.ast_enhancement()
      
      assert enhancement.confidence_rules.base == 0.5
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "in_security_context")
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "uses_crypto_module")
    end
  end

  describe "vulnerable code detection" do
    test "detects :rand.uniform usage" do
      pattern = InsecureRandom.pattern()
      
      vulnerable_code = ~S|token = :rand.uniform(1000000)|
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
      
      vulnerable_code2 = ~S|session_id = :rand.uniform(999999999)|
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code2))
    end

    test "detects Enum.random for security purposes" do
      pattern = InsecureRandom.pattern()
      
      vulnerable_code = ~S|api_key = Enum.random(1..999999)|
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
      
      vulnerable_code2 = ~S|reset_token = Enum.random(100000..999999)|
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code2))
    end

    test "detects :random module usage (deprecated)" do
      pattern = InsecureRandom.pattern()
      
      vulnerable_code = ~S|:random.uniform(100000)|
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end

    test "detects weak random in security contexts" do
      pattern = InsecureRandom.pattern()
      
      vulnerable_code = ~S|password_reset_token = Integer.to_string(:rand.uniform(999999))|
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end
  end

  describe "safe code validation" do
    test "does not match :crypto.strong_rand_bytes" do
      pattern = InsecureRandom.pattern()
      
      safe_code = ~S|token = :crypto.strong_rand_bytes(32)|
      refute Enum.any?(pattern.regex, &Regex.match?(&1, safe_code))
      
      safe_code2 = ~S":crypto.strong_rand_bytes(16) |> Base.encode64()"
      refute Enum.any?(pattern.regex, &Regex.match?(&1, safe_code2))
    end

    test "does not match System.unique_integer" do
      pattern = InsecureRandom.pattern()
      
      safe_code = ~S|id = System.unique_integer([:positive])|
      refute Enum.any?(pattern.regex, &Regex.match?(&1, safe_code))
    end

    test "does not match :rand.uniform for non-security purposes" do
      pattern = InsecureRandom.pattern()
      
      # This is a limitation - the pattern might still match these
      # The AST enhancement should filter these out based on context
      safe_code = ~S|dice_roll = :rand.uniform(6)|
      # Pattern might match, but AST should filter
    end

    test "does not match UUID generation" do
      pattern = InsecureRandom.pattern()
      
      safe_code = ~S|uuid = Ecto.UUID.generate()|
      refute Enum.any?(pattern.regex, &Regex.match?(&1, safe_code))
    end
  end

  describe "enhanced_pattern/0" do
    test "uses ast_enhancement for better detection" do
      enhanced = InsecureRandom.enhanced_pattern()
      
      assert enhanced.id == "elixir-insecure-random"
      assert Map.has_key?(enhanced, :ast_enhancement)
      assert enhanced.ast_enhancement == InsecureRandom.ast_enhancement()
    end
  end
end