defmodule Rsolv.Security.Patterns.Ruby.WeakPasswordStorageTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Ruby.WeakPasswordStorage
  alias Rsolv.Security.Pattern

  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = WeakPasswordStorage.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "ruby-weak-password-storage"
      assert pattern.name == "Weak Password Storage"
      assert pattern.severity == :critical
      assert pattern.type == :cryptographic_failure
      assert pattern.languages == ["ruby"]
    end

    test "includes CWE and OWASP references" do
      pattern = WeakPasswordStorage.pattern()

      assert pattern.cwe_id == "CWE-256"
      assert pattern.owasp_category == "A02:2021"
    end

    test "has multiple regex patterns" do
      pattern = WeakPasswordStorage.pattern()

      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 4
    end
  end

  describe "regex matching" do
    setup do
      pattern = WeakPasswordStorage.pattern()
      {:ok, pattern: pattern}
    end

    test "matches MD5 password hashing", %{pattern: pattern} do
      vulnerable_code = [
        ~S|user.password = Digest::MD5.hexdigest(params[:password])|,
        ~S|password_hash = Digest::MD5.digest(password)|,
        ~S|user.encrypted_password = Digest::MD5.hexdigest(plain_password + salt)|,
        ~S|hash = Digest::MD5.new.hexdigest(user_password)|,
        ~S|password_digest = MD5.hexdigest(password)|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches SHA1 password hashing", %{pattern: pattern} do
      vulnerable_code = [
        ~S|user.password = Digest::SHA1.hexdigest(params[:password])|,
        ~S|password_hash = Digest::SHA1.digest(password)|,
        ~S|user.encrypted_password = Digest::SHA1.hexdigest(plain_password + salt)|,
        ~S|hash = Digest::SHA1.new.digest(user_password)|,
        ~S|password_digest = SHA1.hexdigest(password)|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches SHA256 password hashing without proper salt", %{pattern: pattern} do
      vulnerable_code = [
        ~S|user.password = Digest::SHA256.hexdigest(params[:password])|,
        ~S|password_hash = Digest::SHA256.digest(password)|,
        ~S|user.encrypted_password = Digest::SHA256.hexdigest(plain_password)|,
        ~S|hash = SHA256.hexdigest(user_password)|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches password assignment without hashing", %{pattern: pattern} do
      vulnerable_code = [
        ~S|user.password = params[:password]|,
        ~S|user.encrypted_password = plain_password|,
        ~S|password_field = user_input|,
        ~S|user.password_digest = password|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches simple string hashing", %{pattern: pattern} do
      vulnerable_code = [
        ~S|password = password.crypt(salt)|,
        ~S|hash = password.to_s + "salt"|,
        ~S|encrypted = Base64.encode64(password)|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "does not match secure password storage", %{pattern: pattern} do
      safe_code = [
        ~S|user.password = BCrypt::Password.create(params[:password])|,
        ~S|has_secure_password # Rails built-in|,
        ~S|user.password_digest = BCrypt::Password.create(plain_password)|,
        ~S|password_hash = Argon2::Password.create(password)|,
        ~S|user.encrypted_password = scrypt(password, salt)|,
        ~S|password_reset_token = SecureRandom.hex|,
        # Different field
        ~S|user.email = params[:email]|
      ]

      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should not match: #{code}"
      end
    end

    test "documents regex limitations for comment detection", %{pattern: pattern} do
      # Note: Regex patterns have known limitations with comment detection
      # This is acceptable as AST enhancement will handle such cases
      commented_code = ~S|# user.password = Digest::MD5.hexdigest(password) # Commented|

      # This is a known limitation - regex will match commented code
      assert Enum.any?(pattern.regex, &Regex.match?(&1, commented_code)),
             "Regex patterns are expected to match commented code (AST enhancement handles this)"
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = WeakPasswordStorage.vulnerability_metadata()

      assert metadata.description =~ "password"
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 5
      assert length(metadata.real_world_impact) >= 3
      assert length(metadata.cve_examples) >= 2
    end

    test "includes CVE examples from research" do
      metadata = WeakPasswordStorage.vulnerability_metadata()

      cve_ids = Enum.map(metadata.cve_examples, & &1.id)
      assert Enum.any?(cve_ids, &String.contains?(&1, "CVE-"))
    end

    test "includes proper references" do
      metadata = WeakPasswordStorage.vulnerability_metadata()

      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = WeakPasswordStorage.ast_enhancement()

      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)

      assert enhancement.min_confidence >= 0.7
    end

    test "includes password-specific AST rules" do
      enhancement = WeakPasswordStorage.ast_enhancement()

      assert enhancement.ast_rules.node_type == "AssignmentExpression"
      assert enhancement.ast_rules.password_field_analysis.check_password_fields
    end

    test "has weak hashing algorithm detection" do
      enhancement = WeakPasswordStorage.ast_enhancement()

      assert "MD5" in enhancement.ast_rules.weak_hashing_analysis.weak_algorithms
      assert "SHA1" in enhancement.ast_rules.weak_hashing_analysis.weak_algorithms
    end
  end
end
