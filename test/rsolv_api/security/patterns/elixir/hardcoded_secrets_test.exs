defmodule RsolvApi.Security.Patterns.Elixir.HardcodedSecretsTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Elixir.HardcodedSecrets
  alias RsolvApi.Security.Pattern

  describe "hardcoded_secrets pattern" do
    test "returns correct pattern structure" do
      pattern = HardcodedSecrets.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "elixir-hardcoded-secrets"
      assert pattern.name == "Hardcoded Secrets"
      assert pattern.type == :hardcoded_secret
      assert pattern.severity == :critical
      assert pattern.languages == ["elixir"]
      assert pattern.default_tier == :ai
      assert pattern.cwe_id == "CWE-798"
      assert pattern.owasp_category == "A02:2021"
      
      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects hardcoded API keys in module attributes" do
      pattern = HardcodedSecrets.pattern()
      
      test_cases = [
        ~S|@api_key "sk_live_abcd1234efgh5678"|,
        ~S|@secret_key "pk_test_1234567890abcdef"|,
        ~S|@access_token "ghp_xxxxxxxxxxxxxxxxxxxx"|,
        ~S|@auth_token "xoxb-1234567890-abcdefghijklmnop"|
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects hardcoded secrets in variable assignments" do
      pattern = HardcodedSecrets.pattern()
      
      test_cases = [
        ~S|secret_key = "very_secret_password_12345"|,
        ~S|password = "admin_password_2024"|,
        ~S|token = "Bearer abc123def456ghi789"|,
        ~S|private_key = "-----BEGIN PRIVATE KEY-----"|
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects hardcoded secrets in function definitions" do
      pattern = HardcodedSecrets.pattern()
      
      test_cases = [
        ~S|def get_api_key, do: "sk_test_abcdef1234567890"|,
        ~S|defp secret_password(), do: "super_secret_123"|,
        ~S|def auth_header, do: {"Authorization", "Bearer hardcoded_token"}|
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects hardcoded database credentials" do
      pattern = HardcodedSecrets.pattern()
      
      test_cases = [
        ~S|database_url = "postgres://user:secret123@localhost/myapp"|,
        ~S|@db_password "admin_db_password_2024"|,
        ~S|mysql_config = [username: "root", password: "mysql_secret_456"]|
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects hardcoded encryption keys" do
      pattern = HardcodedSecrets.pattern()
      
      test_cases = [
        ~S|@encryption_key "32charencryptionkey123456789012"|,
        ~S|private_key = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC"|,
        ~S|jwt_secret = "my-super-secret-jwt-key-12345"|
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects hardcoded cloud service keys" do
      pattern = HardcodedSecrets.pattern()
      
      test_cases = [
        ~S|@aws_access_key "AKIAIOSFODNN7EXAMPLE"|,
        ~S|gcp_key = "AIzaSyDaGmWKa4JsXZ-HjGw3_D5wsdkfSDKFSDKF"|,
        ~S|github_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"|
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "does not detect safe environment variable usage" do
      pattern = HardcodedSecrets.pattern()
      
      safe_code = [
        ~S|@api_key System.get_env("API_KEY")|,
        ~S|secret_key = Application.get_env(:myapp, :secret_key)|,
        ~S|password = System.fetch_env!("DATABASE_PASSWORD")|,
        ~S|config :myapp, secret_key_base: System.get_env("SECRET_KEY_BASE")|
      ]
      
      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "does not detect short or test values" do
      pattern = HardcodedSecrets.pattern()
      
      safe_code = [
        ~S|@api_key "test"|,
        ~S|password = ""|,
        ~S|secret = "abc"|,
        ~S|token = "12345"|
      ]
      
      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "does not detect comments or documentation" do
      pattern = HardcodedSecrets.pattern()
      
      safe_code = [
        ~S|# @api_key "sk_live_abcd1234efgh5678"|,
        ~S|# TODO: Replace with System.get_env("SECRET_KEY")|,
        ~S|@doc "Set password to a secure value like 'my_secure_password_123'"|
      ]
      
      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = HardcodedSecrets.vulnerability_metadata()
      
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

    test "vulnerability metadata contains secrets-specific information" do
      metadata = HardcodedSecrets.vulnerability_metadata()
      
      assert String.contains?(metadata.attack_vectors, "source code")
      assert String.contains?(metadata.business_impact, "financial")
      assert String.contains?(metadata.technical_impact, "unauthorized")
      assert String.contains?(metadata.safe_alternatives, "environment")
      assert String.contains?(metadata.prevention_tips, "runtime")
    end

    test "includes AST enhancement rules" do
      enhancement = HardcodedSecrets.ast_enhancement()
      
      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has secrets-specific rules" do
      enhancement = HardcodedSecrets.ast_enhancement()
      
      assert enhancement.context_rules.exclude_test_files
      assert enhancement.context_rules.secret_indicators
      assert enhancement.ast_rules.string_analysis
      assert enhancement.ast_rules.variable_analysis
      assert enhancement.confidence_rules.adjustments.test_context_penalty
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = HardcodedSecrets.enhanced_pattern()
      
      assert enhanced.id == "elixir-hardcoded-secrets"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = HardcodedSecrets.pattern()
      
      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end
  end
end