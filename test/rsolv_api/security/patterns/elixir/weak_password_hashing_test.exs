defmodule RsolvApi.Security.Patterns.Elixir.WeakPasswordHashingTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Elixir.WeakPasswordHashing
  alias RsolvApi.Security.Pattern

  describe "weak_password_hashing pattern" do
    test "returns correct pattern structure" do
      pattern = WeakPasswordHashing.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "elixir-weak-password-hashing"
      assert pattern.name == "Weak Password Hashing"
      assert pattern.type == :weak_crypto
      assert pattern.severity == :high
      assert pattern.languages == ["elixir"]
      assert pattern.cwe_id == "CWE-916"
      assert pattern.owasp_category == "A02:2021"
      
      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects crypto.hash with password" do
      pattern = WeakPasswordHashing.pattern()
      
      test_cases = [
        ~S|:crypto.hash(:sha256, password <> salt)|,
        ~S|:crypto.hash(:sha, password)|,
        ~S|:crypto.hash(:md5, password_hash)|,
        ~S|:crypto.hash(:sha512, user_password <> salt)|,
        ~S|:crypto.hash(:sha224, password_plain)|
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects Base.encode with password hashing" do
      pattern = WeakPasswordHashing.pattern()
      
      test_cases = [
        ~S|Base.encode16(:crypto.hash(:sha256, password))|,
        ~S|Base.encode64(:crypto.hash(:sha, user_password))|,
        ~S|Base.encode32(:crypto.hash(:md5, password_data))|,
        ~S|Base.url_encode64(:crypto.hash(:sha512, password))|,
        ~S|Base.hex_encode32(:crypto.hash(:sha256, pass <> salt))|
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects simple hashing assignments" do
      pattern = WeakPasswordHashing.pattern()
      
      test_cases = [
        ~S|password_hash = :crypto.hash(:sha256, password)|,
        ~S|pwd_hash = :crypto.hash(:sha, plain_password)|,
        ~S|hashed_password = :crypto.hash(:md5, user_password)|,
        ~S|pass_hash = :crypto.hash(:sha512, password_string)|,
        ~S|user_password_hash = :crypto.hash(:sha256, pwd)|
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects multi-line password hashing" do
      pattern = WeakPasswordHashing.pattern()
      
      test_cases = [
        ~S"""
        hashed = 
          :crypto.hash(:sha256, password)
          |> Base.encode16()
        """,
        ~S"""
        password_hash =
          user_password
          |> Kernel.<>(salt)
          |> then(&:crypto.hash(:sha256, &1))
        """,
        ~S"""
        def hash_password(password) do
          :crypto.hash(:sha256, password <> get_salt())
        end
        """
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects legacy crypto functions" do
      pattern = WeakPasswordHashing.pattern()
      
      test_cases = [
        ~S|:crypto.sha256(password)|,
        ~S|:crypto.sha(password <> salt)|,
        ~S|:crypto.md5(user_password)|,
        ~S|:crypto.sha512(password_plain)|,
        ~S|:erlang.md5(password)|
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "does not detect secure password hashing" do
      pattern = WeakPasswordHashing.pattern()
      
      safe_code = [
        # Argon2
        ~S|Argon2.hash_pwd_salt(password)|,
        ~S|Argon2.verify_pass(password, hash)|,
        ~S|Argon2.hash_pwd_salt(password, argon2_params())|,
        # Bcrypt
        ~S|Bcrypt.hash_pwd_salt(password)|,
        ~S|Bcrypt.verify_pass(password, hash)|,
        ~S|Bcrypt.hash_pwd_salt(password, log_rounds: 12)|,
        # Pbkdf2
        ~S|Pbkdf2.hash_pwd_salt(password)|,
        ~S|Pbkdf2.verify_pass(password, hash)|,
        # Comments
        ~S|# :crypto.hash(:sha256, password)|
      ]
      
      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "does not detect comments or documentation" do
      pattern = WeakPasswordHashing.pattern()
      
      safe_code = [
        ~S|# :crypto.hash(:sha256, password)|,
        ~S|@doc "Never use :crypto.hash(:sha256, password)"|,
        ~S|# TODO: Replace :crypto.hash(:md5, password) with Argon2|,
        ~S"""
        # Bad example:
        # :crypto.hash(:sha256, password)
        """
      ]
      
      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = WeakPasswordHashing.vulnerability_metadata()
      
      assert metadata.attack_vectors
      assert metadata.business_impact  
      assert metadata.technical_impact
      assert metadata.likelihood
      assert metadata.cve_examples
      assert metadata.compliance_standards
      assert metadata.remediation_steps
      assert metadata.prevention_tips
      assert metadata.detection_methods
      assert metadata.safe_alternatives
    end

    test "vulnerability metadata contains password hashing specific information" do
      metadata = WeakPasswordHashing.vulnerability_metadata()
      
      assert String.contains?(metadata.attack_vectors, "brute")
      assert String.contains?(metadata.business_impact, "credential")
      assert String.contains?(metadata.technical_impact, "rainbow")
      assert String.contains?(metadata.safe_alternatives, "Argon2")
      assert String.contains?(metadata.prevention_tips, "computational")
    end

    test "includes AST enhancement rules" do
      enhancement = WeakPasswordHashing.ast_enhancement()
      
      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has password hashing specific rules" do
      enhancement = WeakPasswordHashing.ast_enhancement()
      
      assert enhancement.context_rules.weak_algorithms
      assert enhancement.context_rules.strong_algorithms
      assert enhancement.ast_rules.password_analysis
      assert enhancement.confidence_rules.adjustments.strong_algorithm_penalty
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = WeakPasswordHashing.enhanced_pattern()
      
      assert enhanced.id == "elixir-weak-password-hashing"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = WeakPasswordHashing.pattern()
      
      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end
  end
end