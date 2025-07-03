defmodule Rsolv.Security.Patterns.Ruby.HardcodedSecretsTest do
  use ExUnit.Case, async: true
  
  alias Rsolv.Security.Patterns.Ruby.HardcodedSecrets
  alias Rsolv.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = HardcodedSecrets.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "ruby-hardcoded-secrets"
      assert pattern.name == "Hardcoded Secrets"
      assert pattern.severity == :critical
      assert pattern.type == :sensitive_data_exposure
      assert pattern.languages == ["ruby"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = HardcodedSecrets.pattern()
      
      assert pattern.cwe_id == "CWE-798"
      assert pattern.owasp_category == "A07:2021"
    end
    
    test "has multiple regex patterns" do
      pattern = HardcodedSecrets.pattern()
      
      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 5
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = HardcodedSecrets.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches hardcoded password assignments", %{pattern: pattern} do
      vulnerable_code = [
        ~S|password = "super_secret123"|,
        ~S|PASSWORD = 'admin123'|,
        ~S|config.password = "hardcoded_pass"|,
        ~S|user_password = "secret"|,
        ~S|db_password = "mysql123"|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches hardcoded API key assignments", %{pattern: pattern} do
      vulnerable_code = [
        ~S|api_key = "sk_test_123456"|,
        ~S|API_KEY = "ak_live_abcdef"|,
        ~S|config.api_key = "hardcoded_key"|,
        ~S|stripe_key = "rk_test_xyz"|,
        ~S|github_token = "ghp_abcdefghijklmnopqrstuvwxyz123456"|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches hardcoded secret assignments", %{pattern: pattern} do
      vulnerable_code = [
        ~S|secret = "my_secret_key"|,
        ~S|SECRET_KEY = "hardcoded_secret"|,
        ~S|config.secret_key = "static_secret"|,
        ~S|jwt_secret = "supersecret"|,
        ~S|app_secret = "hardcoded"|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches hardcoded AWS credentials", %{pattern: pattern} do
      vulnerable_code = [
        ~S|AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"|,
        ~S|AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"|,
        ~S|aws_access_key = "AKIA1234567890"|,
        ~S|aws_secret = "abcdef1234567890"|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches hardcoded private keys", %{pattern: pattern} do
      vulnerable_code = [
        ~S|private_key = "-----BEGIN PRIVATE KEY-----"|,
        ~S|PRIVATE_KEY = "rsa_private_key_here"|,
        ~S|config.private_key = "hardcoded_key"|,
        ~S|ssl_private_key = "-----BEGIN RSA PRIVATE KEY-----"|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches hardcoded tokens and credentials", %{pattern: pattern} do
      vulnerable_code = [
        ~S|auth_token = "Bearer abcdef123456"|,
        ~S|access_token = "ya29.AHES6ZRVmB7fkLtd1"|,
        ~S|session_token = "sess_12345"|,
        ~S|database_url = "postgres://user:pass@host:5432/db"|,
        ~S|redis_url = "redis://user:pass@localhost:6379"|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe credential handling", %{pattern: pattern} do
      safe_code = [
        ~S|password = ENV['DATABASE_PASSWORD']|,
        ~S|api_key = Rails.application.credentials.api_key|,
        ~S|secret = KeyVault.fetch('app_secret')|,
        ~S|config.password = SecureRandom.hex(16)|,
        ~S|password = gets.chomp|,
        ~S|puts "Enter your password:"|,
        ~S|ENV['API_KEY'] = user_input|
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should not match: #{code}"
      end
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = HardcodedSecrets.vulnerability_metadata()
      
      assert metadata.description =~ "hardcoded"
      assert length(metadata.references) >= 3
      assert length(metadata.attack_vectors) >= 5
      assert length(metadata.real_world_impact) >= 3
      assert length(metadata.cve_examples) >= 4
    end
    
    test "includes real-world incident references" do
      metadata = HardcodedSecrets.vulnerability_metadata()
      
      impact = Enum.join(metadata.real_world_impact, " ")
      assert impact =~ "CVE-2013-0156" || impact =~ "Rails" || impact =~ "GitHub"
    end
    
    test "includes proper references" do
      metadata = HardcodedSecrets.vulnerability_metadata()
      
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = HardcodedSecrets.ast_enhancement()
      
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.8
    end
    
    test "includes credential-specific AST rules" do
      enhancement = HardcodedSecrets.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "Assignment"
      assert "password" in enhancement.ast_rules.variable_patterns
    end
    
    test "has proper context detection" do
      enhancement = HardcodedSecrets.ast_enhancement()
      
      assert enhancement.context_rules.check_assignment_context
      assert "ENV" in enhancement.context_rules.safe_sources
    end
  end
end