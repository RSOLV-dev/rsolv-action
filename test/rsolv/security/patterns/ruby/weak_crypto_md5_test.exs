defmodule Rsolv.Security.Patterns.Ruby.WeakCryptoMd5Test do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Ruby.WeakCryptoMd5
  alias Rsolv.Security.Pattern

  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = WeakCryptoMd5.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "ruby-weak-crypto-md5"
      assert pattern.name == "Weak Cryptography - MD5 Usage"
      assert pattern.severity == :medium
      assert pattern.type == :cryptographic_failure
      assert pattern.languages == ["ruby"]
    end

    test "includes CWE and OWASP references" do
      pattern = WeakCryptoMd5.pattern()

      assert pattern.cwe_id == "CWE-328"
      assert pattern.owasp_category == "A02:2021"
    end

    test "has multiple regex patterns" do
      pattern = WeakCryptoMd5.pattern()

      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 3
    end
  end

  describe "regex matching" do
    setup do
      pattern = WeakCryptoMd5.pattern()
      {:ok, pattern: pattern}
    end

    test "matches Digest::MD5 usage", %{pattern: pattern} do
      vulnerable_code = [
        "Digest::MD5.hexdigest(password)",
        "Digest::MD5.digest(data)",
        "Digest::MD5.base64digest(input)",
        "hash = Digest::MD5.new"
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches OpenSSL MD5 usage", %{pattern: pattern} do
      vulnerable_code = [
        ~S|OpenSSL::Digest.new('MD5')|,
        ~S|OpenSSL::Digest::MD5.new|,
        ~S|OpenSSL::Digest.new("MD5")|,
        ~S|OpenSSL::Digest::MD5.hexdigest(data)|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches .md5 method calls", %{pattern: pattern} do
      vulnerable_code = [
        "password.md5",
        "data.md5()",
        "string.md5.hexdigest"
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "does not match safe cryptographic functions", %{pattern: pattern} do
      safe_code = [
        "Digest::SHA256.hexdigest(data)",
        "BCrypt::Password.create(password)",
        "OpenSSL::Digest.new('SHA256')",
        "Argon2::Password.create(pass)"
      ]

      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should not match: #{code}"
      end
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = WeakCryptoMd5.vulnerability_metadata()

      assert metadata.description =~ "MD5"
      assert length(metadata.references) >= 3
      assert length(metadata.attack_vectors) >= 3
      assert length(metadata.real_world_impact) >= 3
      assert length(metadata.cve_examples) >= 3
    end

    test "includes real-world incidents" do
      metadata = WeakCryptoMd5.vulnerability_metadata()

      impact = Enum.join(metadata.real_world_impact, " ")
      assert impact =~ "LinkedIn" || impact =~ "Adobe"
    end

    test "includes proper references" do
      metadata = WeakCryptoMd5.vulnerability_metadata()

      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = WeakCryptoMd5.ast_enhancement()

      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)

      assert enhancement.min_confidence >= 0.6
    end

    test "includes crypto-specific AST rules" do
      enhancement = WeakCryptoMd5.ast_enhancement()

      assert enhancement.ast_rules.node_type == "ConstantAccess"
      assert "MD5" in enhancement.ast_rules.constant_names
    end

    test "has proper context detection" do
      enhancement = WeakCryptoMd5.ast_enhancement()

      assert enhancement.context_rules.check_usage_context
      assert "checksum" in enhancement.context_rules.non_security_contexts
    end
  end
end
