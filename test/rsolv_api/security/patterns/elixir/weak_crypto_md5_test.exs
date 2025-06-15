defmodule RsolvApi.Security.Patterns.Elixir.WeakCryptoMd5Test do
  use ExUnit.Case, async: true

  alias RsolvApi.Security.Patterns.Elixir.WeakCryptoMd5
  alias RsolvApi.Security.Pattern

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = WeakCryptoMd5.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "elixir-weak-crypto-md5"
      assert pattern.name == "Weak Cryptography - MD5"
      assert pattern.type == :weak_crypto
      assert pattern.severity == :medium
      assert pattern.languages == ["elixir"]
      assert pattern.cwe_id == "CWE-327"
      assert pattern.owasp_category == "A02:2021"
      assert pattern.default_tier == :public
      assert is_list(pattern.regex) or pattern.regex.__struct__ == Regex
    end

    test "pattern has comprehensive test cases" do
      pattern = WeakCryptoMd5.pattern()
      
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
      assert length(pattern.test_cases.vulnerable) >= 3
      assert length(pattern.test_cases.safe) >= 3
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = WeakCryptoMd5.vulnerability_metadata()
      
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

    test "includes weak crypto information" do
      metadata = WeakCryptoMd5.vulnerability_metadata()
      
      # Should mention MD5 weaknesses
      assert String.contains?(metadata.description, "MD5") or
             String.contains?(metadata.description, "collision")
      
      # Should mention safe alternatives
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "SHA256")) or
             Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "Argon2"))
    end

    test "references include CWE-327 and OWASP A02:2021" do
      metadata = WeakCryptoMd5.vulnerability_metadata()
      
      cwe_ref = Enum.find(metadata.references, &(&1.type == :cwe))
      assert cwe_ref.id == "CWE-327"
      
      owasp_ref = Enum.find(metadata.references, &(&1.type == :owasp))
      assert owasp_ref.id == "A02:2021"
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper AST enhancement structure" do
      enhancement = WeakCryptoMd5.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.6
    end

    test "AST rules check for crypto usage" do
      enhancement = WeakCryptoMd5.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert Map.has_key?(enhancement.ast_rules, :crypto_analysis)
      assert enhancement.ast_rules.crypto_analysis.check_crypto_module == true
    end

    test "context rules identify legitimate uses" do
      enhancement = WeakCryptoMd5.ast_enhancement()
      
      assert Map.has_key?(enhancement.context_rules, :legitimate_uses)
      assert "checksum" in enhancement.context_rules.legitimate_uses
      assert "file_integrity" in enhancement.context_rules.legitimate_uses
    end

    test "confidence adjustments for security context" do
      enhancement = WeakCryptoMd5.ast_enhancement()
      
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "in_security_context")
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "checksum_usage")
    end
  end

  describe "vulnerable code detection" do
    test "detects :crypto.hash(:md5, data)" do
      pattern = WeakCryptoMd5.pattern()
      
      vulnerable_code = ~S|:crypto.hash(:md5, password)|
      assert pattern_matches?(pattern, vulnerable_code)
      
      vulnerable_code2 = ~S|:crypto.hash(:md5, user_data)|
      assert pattern_matches?(pattern, vulnerable_code2)
    end

    test "detects Base.encode16 with MD5" do
      pattern = WeakCryptoMd5.pattern()
      
      vulnerable_code = ~S|Base.encode16(:crypto.hash(:md5, data))|
      assert pattern_matches?(pattern, vulnerable_code)
    end

    test "detects :crypto.md5 function" do
      pattern = WeakCryptoMd5.pattern()
      
      vulnerable_code = ~S|:crypto.md5(data)|
      assert pattern_matches?(pattern, vulnerable_code)
    end

    test "detects :erlang.md5 function" do
      pattern = WeakCryptoMd5.pattern()
      
      vulnerable_code = ~S|:erlang.md5(content)|
      assert pattern_matches?(pattern, vulnerable_code)
    end

    test "detects MD5 with variable algorithms" do
      pattern = WeakCryptoMd5.pattern()
      
      vulnerable_code = ~S|algorithm = :md5
:crypto.hash(algorithm, data)|
      assert pattern_matches?(pattern, vulnerable_code)
    end

    test "detects piped MD5 usage" do
      pattern = WeakCryptoMd5.pattern()
      
      vulnerable_code = "data |> :crypto.hash(:md5, _)"
      assert pattern_matches?(pattern, vulnerable_code)
    end
  end

  describe "safe code validation" do
    test "does not match SHA256 usage" do
      pattern = WeakCryptoMd5.pattern()
      
      safe_code = ~S|:crypto.hash(:sha256, data)|
      refute pattern_matches?(pattern, safe_code)
    end

    test "does not match Argon2 usage" do
      pattern = WeakCryptoMd5.pattern()
      
      safe_code = ~S|Argon2.hash_pwd_salt(password)|
      refute pattern_matches?(pattern, safe_code)
    end

    test "does not match Bcrypt usage" do
      pattern = WeakCryptoMd5.pattern()
      
      safe_code = ~S|Bcrypt.hash_pwd_salt(password)|
      refute pattern_matches?(pattern, safe_code)
    end

    test "does not match simple comments about MD5" do
      pattern = WeakCryptoMd5.pattern()
      
      # Note: Our pattern includes function name detection, so some comments might match
      # This is a known trade-off for better detection
      safe_code = ~S|# MD5 is not secure for passwords|
      refute pattern_matches?(pattern, safe_code)
    end
  end

  describe "enhanced_pattern/0" do
    test "uses ast_enhancement for better detection" do
      enhanced = WeakCryptoMd5.enhanced_pattern()
      
      assert enhanced.id == "elixir-weak-crypto-md5"
      assert Map.has_key?(enhanced, :ast_enhancement)
      assert enhanced.ast_enhancement == WeakCryptoMd5.ast_enhancement()
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