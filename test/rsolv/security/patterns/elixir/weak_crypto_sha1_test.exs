defmodule Rsolv.Security.Patterns.Elixir.WeakCryptoSha1Test do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Elixir.WeakCryptoSha1
  alias Rsolv.Security.Pattern

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = WeakCryptoSha1.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "elixir-weak-crypto-sha1"
      assert pattern.name == "Weak Cryptography - SHA1"
      assert pattern.type == :weak_crypto
      assert pattern.severity == :medium
      assert pattern.languages == ["elixir"]
      assert pattern.cwe_id == "CWE-327"
      assert pattern.owasp_category == "A02:2021"
      assert is_list(pattern.regex) or pattern.regex.__struct__ == Regex
    end

    test "pattern has comprehensive test cases" do
      pattern = WeakCryptoSha1.pattern()

      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
      assert length(pattern.test_cases.vulnerable) >= 3
      assert length(pattern.test_cases.safe) >= 3
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = WeakCryptoSha1.vulnerability_metadata()

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

    test "includes SHA1 deprecation information" do
      metadata = WeakCryptoSha1.vulnerability_metadata()

      # Should mention SHA1 weaknesses and NIST deprecation
      assert String.contains?(metadata.description, "SHA") or
               String.contains?(metadata.description, "collision") or
               String.contains?(metadata.description, "deprecated")

      # Should mention safe alternatives
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "SHA256")) or
               Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "SHA-2"))
    end

    test "references include CWE-327 and OWASP A02:2021" do
      metadata = WeakCryptoSha1.vulnerability_metadata()

      cwe_ref = Enum.find(metadata.references, &(&1.type == :cwe))
      assert cwe_ref.id == "CWE-327"

      owasp_ref = Enum.find(metadata.references, &(&1.type == :owasp))
      assert owasp_ref.id == "A02:2021"
    end

    test "includes SHAttered attack and NIST deprecation" do
      metadata = WeakCryptoSha1.vulnerability_metadata()

      # Should reference SHAttered attack or NIST deprecation
      references_text = Enum.map(metadata.references, & &1.title) |> Enum.join(" ")

      assert String.contains?(references_text, "SHAttered") or
               String.contains?(references_text, "NIST") or
               String.contains?(references_text, "collision")
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper AST enhancement structure" do
      enhancement = WeakCryptoSha1.ast_enhancement()

      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)

      assert enhancement.min_confidence >= 0.6
    end

    test "AST rules check for crypto usage" do
      enhancement = WeakCryptoSha1.ast_enhancement()

      assert enhancement.ast_rules.node_type == "CallExpression"
      assert Map.has_key?(enhancement.ast_rules, :crypto_analysis)
      assert enhancement.ast_rules.crypto_analysis.check_crypto_module == true
    end

    test "context rules identify legitimate uses" do
      enhancement = WeakCryptoSha1.ast_enhancement()

      assert Map.has_key?(enhancement.context_rules, :legitimate_uses)
      assert "git" in enhancement.context_rules.legitimate_uses
      assert "checksum" in enhancement.context_rules.legitimate_uses
    end

    test "confidence adjustments for security vs non-security context" do
      enhancement = WeakCryptoSha1.ast_enhancement()

      assert Map.has_key?(enhancement.confidence_rules.adjustments, "git_usage")
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "in_security_context")
    end
  end

  describe "vulnerable code detection" do
    test "detects :crypto.hash(:sha, data)" do
      pattern = WeakCryptoSha1.pattern()

      vulnerable_code = ":crypto.hash(:sha, password)"
      assert pattern_matches?(pattern, vulnerable_code)

      vulnerable_code2 = ":crypto.hash(:sha, user_data)"
      assert pattern_matches?(pattern, vulnerable_code2)
    end

    test "detects Base.encode16 with SHA1" do
      pattern = WeakCryptoSha1.pattern()

      vulnerable_code = "Base.encode16(:crypto.hash(:sha, data))"
      assert pattern_matches?(pattern, vulnerable_code)
    end

    test "detects :crypto.sha function" do
      pattern = WeakCryptoSha1.pattern()

      vulnerable_code = ":crypto.sha(data)"
      assert pattern_matches?(pattern, vulnerable_code)
    end

    test "detects :erlang.sha function" do
      pattern = WeakCryptoSha1.pattern()

      vulnerable_code = ":erlang.sha(content)"
      assert pattern_matches?(pattern, vulnerable_code)
    end

    test "detects SHA1 with variable algorithms" do
      pattern = WeakCryptoSha1.pattern()

      vulnerable_code = """
      algorithm = :sha
      :crypto.hash(algorithm, data)
      """

      assert pattern_matches?(pattern, vulnerable_code)
    end

    test "detects piped SHA1 usage" do
      pattern = WeakCryptoSha1.pattern()

      vulnerable_code = "data |> :crypto.hash(:sha, _)"
      assert pattern_matches?(pattern, vulnerable_code)
    end

    test "detects HMAC with SHA1" do
      pattern = WeakCryptoSha1.pattern()

      vulnerable_code = ":crypto.hmac(:sha, key, message)"
      assert pattern_matches?(pattern, vulnerable_code)
    end
  end

  describe "safe code validation" do
    test "does not match SHA256 usage" do
      pattern = WeakCryptoSha1.pattern()

      safe_code = ":crypto.hash(:sha256, data)"
      refute pattern_matches?(pattern, safe_code)
    end

    test "does not match SHA512 usage" do
      pattern = WeakCryptoSha1.pattern()

      safe_code = ":crypto.hash(:sha512, data)"
      refute pattern_matches?(pattern, safe_code)
    end

    test "does not match BLAKE2 usage" do
      pattern = WeakCryptoSha1.pattern()

      safe_code = ":crypto.hash(:blake2b, data)"
      refute pattern_matches?(pattern, safe_code)
    end

    test "does not match Git usage comments" do
      pattern = WeakCryptoSha1.pattern()

      # Comments about Git SHA1 usage should be excluded
      safe_code = "# Git uses SHA1 for commit hashes"
      refute pattern_matches?(pattern, safe_code)
    end

    test "does not match checksum context comments" do
      pattern = WeakCryptoSha1.pattern()

      # Non-security checksum usage
      safe_code = "# SHA1 checksum for file integrity"
      refute pattern_matches?(pattern, safe_code)
    end
  end

  describe "enhanced_pattern/0" do
    test "uses ast_enhancement for better detection" do
      enhanced = WeakCryptoSha1.enhanced_pattern()

      assert enhanced.id == "elixir-weak-crypto-sha1"
      assert Map.has_key?(enhanced, :ast_enhancement)
      assert enhanced.ast_enhancement == WeakCryptoSha1.ast_enhancement()
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
