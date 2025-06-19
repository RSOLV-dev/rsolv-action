defmodule RsolvApi.Security.Patterns.Javascript.HardcodedSecretApiKeyTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Javascript.HardcodedSecretApiKey
  alias RsolvApi.Security.Pattern
  
  describe "HardcodedSecretApiKey pattern" do
    test "pattern/0 returns correct structure" do
      pattern = HardcodedSecretApiKey.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-hardcoded-secret-api-key"
      assert pattern.name == "Hardcoded API Key"
      assert pattern.description == "API keys should not be hardcoded in source code"
      assert pattern.type == :hardcoded_secret
      assert pattern.severity == :high
      assert pattern.languages == ["javascript", "typescript"]
      assert pattern.default_tier == :ai
      assert pattern.cwe_id == "CWE-798"
      assert pattern.owasp_category == "A07:2021"
      assert is_binary(pattern.recommendation)
      assert is_map(pattern.test_cases)
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
    end
    
    test "pattern detects vulnerable hardcoded API key usage" do
      pattern = HardcodedSecretApiKey.pattern()
      
      vulnerable_cases = [
        ~S|const apiKey = "sk-1234567890abcdef"|,
        ~S|const API_KEY = "abcd1234efgh5678ijkl"|,
        ~S|let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"|,
        ~S|var config = { apiKey: "prod_live_abc123def456" }|,
        ~S|const api_secret = "secret_key_12345678901234567890"|,
        ~S|let authToken = `bearer_token_abcdefghijklmnop`|,
        ~S|const API_SECRET = "live_api_secret_xyz789"|,
        ~S|api-key: "service_account_key_123456789"|,
        ~S|const stripe = { api_key: "sk_live_1234567890123456" }|,
        ~S|let github_token = "ghp_abcdefghijklmnopqrstuvwxyz123456"|
      ]
      
      for code <- vulnerable_cases do
        assert Regex.match?(pattern.regex, code), 
          "Failed to match vulnerable code: #{code}"
      end
    end
    
    test "pattern does not match safe API key handling" do
      pattern = HardcodedSecretApiKey.pattern()
      
      safe_cases = [
        ~S|const apiKey = process.env.API_KEY|,
        ~S|const token = getTokenFromVault()|,
        ~S|const apiSecret = await keyManager.getKey('api-secret')|,
        ~S|let apiKey = config.get('stripe.apiKey')|,
        ~S|const token = await oauth.getAccessToken()|,
        ~S|var apiKey = prompt("Enter API key:")|,
        ~S|const key = generateApiKey()|,
        ~S|// apiKey should be stored securely|,
        ~S|const keyField = document.getElementById("apiKey")|,
        ~S|function validateApiKey(key) { return key.length > 16; }|,
        ~S|const API_URL = "https://api.example.com"|,
        ~S|console.log("API key validation failed")|,
        ~S|const shortKey = "abc"|,
        ~S|let tempKey = "test123"|,
        ~S|const mockKey = "fake_key"|
      ]
      
      for code <- safe_cases do
        refute Regex.match?(pattern.regex, code),
          "Incorrectly matched safe code: #{code}"
      end
    end
    
    test "vulnerability_metadata/0 returns comprehensive metadata" do
      metadata = HardcodedSecretApiKey.vulnerability_metadata()
      
      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert String.length(metadata.description) > 100
      
      # Check references structure
      assert is_list(metadata.references)
      assert length(metadata.references) >= 4
      
      for ref <- metadata.references do
        assert Map.has_key?(ref, :type)
        assert Map.has_key?(ref, :url)
        assert ref.type in [:cwe, :owasp, :nist, :research, :sans, :vendor]
        assert String.starts_with?(ref.url, "http")
      end
      
      # Check attack vectors
      assert is_list(metadata.attack_vectors)
      assert length(metadata.attack_vectors) >= 5
      
      # Check real world impact
      assert is_list(metadata.real_world_impact)
      assert length(metadata.real_world_impact) >= 5
      
      # Check CVE examples
      assert is_list(metadata.cve_examples)
      assert length(metadata.cve_examples) >= 3
      
      for cve <- metadata.cve_examples do
        assert Map.has_key?(cve, :id)
        assert Map.has_key?(cve, :description)
        assert Map.has_key?(cve, :severity)
        assert String.starts_with?(cve.id, "CVE-")
        assert cve.severity in ["low", "medium", "high", "critical"]
      end
      
      # Check safe alternatives
      assert is_list(metadata.safe_alternatives)
      assert length(metadata.safe_alternatives) >= 5
      
      # Check detection notes
      assert is_binary(metadata.detection_notes)
      assert String.length(metadata.detection_notes) > 50
    end
    
    test "applies_to_file?/1 works correctly" do
      # JavaScript and TypeScript files
      assert HardcodedSecretApiKey.applies_to_file?("test.js")
      assert HardcodedSecretApiKey.applies_to_file?("app.jsx")
      assert HardcodedSecretApiKey.applies_to_file?("server.ts")
      assert HardcodedSecretApiKey.applies_to_file?("component.tsx")
      assert HardcodedSecretApiKey.applies_to_file?("module.mjs")
      
      # Non-JavaScript files
      refute HardcodedSecretApiKey.applies_to_file?("test.py")
      refute HardcodedSecretApiKey.applies_to_file?("app.rb")
      refute HardcodedSecretApiKey.applies_to_file?("server.php")
    end
    
    test "applies_to_file?/2 detects embedded API key assignments" do
      # Should detect API key assignments in any file
      content_with_api_key = ~S|const stripeApiKey = "sk_live_1234567890abcdef";|
      assert HardcodedSecretApiKey.applies_to_file?("config.json", content_with_api_key)
      
      # Should not match files without API key assignments
      content_without_api_key = ~S|const databaseUrl = "postgresql://localhost:5432/app";|
      refute HardcodedSecretApiKey.applies_to_file?("config.json", content_without_api_key)
    end
    
    test "ast_enhancement/0 returns correct structure" do
      enhancement = HardcodedSecretApiKey.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      # Check AST rules
      assert is_map(enhancement.ast_rules)
      assert enhancement.ast_rules.node_type == "VariableDeclarator"
      assert is_list(enhancement.ast_rules.value_types)
      
      # Check context rules
      assert is_map(enhancement.context_rules)
      assert is_list(enhancement.context_rules.exclude_paths)
      assert is_list(enhancement.context_rules.safe_patterns)
      
      # Check confidence rules
      assert is_map(enhancement.confidence_rules)
      assert is_number(enhancement.confidence_rules.base)
      assert is_map(enhancement.confidence_rules.adjustments)
      
      # Check min confidence
      assert is_number(enhancement.min_confidence)
      assert enhancement.min_confidence >= 0.0
      assert enhancement.min_confidence <= 1.0
    end
    
    test "AST rules specify API key assignment patterns" do
      enhancement = HardcodedSecretApiKey.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "VariableDeclarator"
      assert "Literal" in enhancement.ast_rules.value_types
      assert is_map(enhancement.ast_rules.identifier_check)
      assert Regex.match?(enhancement.ast_rules.identifier_check.pattern, "apiKey")
    end
    
    test "context rules exclude test files and check for API key patterns" do
      enhancement = HardcodedSecretApiKey.ast_enhancement()
      
      # Should exclude test directories
      exclude_paths = enhancement.context_rules.exclude_paths
      assert Enum.any?(exclude_paths, &Regex.match?(&1, "test/"))
      assert Enum.any?(exclude_paths, &Regex.match?(&1, ".env.example"))
      
      # Should check for API key patterns
      assert is_list(enhancement.context_rules.api_key_patterns)
      assert "sk_" in enhancement.context_rules.api_key_patterns
    end
    
    test "confidence scoring adjusts for API key context" do
      enhancement = HardcodedSecretApiKey.ast_enhancement()
      
      adjustments = enhancement.confidence_rules.adjustments
      
      # Should have positive adjustments for clear vulnerabilities
      assert adjustments["known_api_key_format"] > 0
      assert adjustments["production_prefix"] > 0
      
      # Should have negative adjustments for safe patterns
      assert adjustments["environment_variable"] < 0
      assert adjustments["test_key"] < 0
      assert adjustments["short_value"] < 0
    end
  end
end