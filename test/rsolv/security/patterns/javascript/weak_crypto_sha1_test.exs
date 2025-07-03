defmodule Rsolv.Security.Patterns.Javascript.WeakCryptoSha1Test do
  use ExUnit.Case, async: true
  
  alias Rsolv.Security.Patterns.Javascript.WeakCryptoSha1
  alias Rsolv.Security.Pattern
  
  describe "WeakCryptoSha1 pattern" do
    test "pattern/0 returns correct structure" do
      pattern = WeakCryptoSha1.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-weak-crypto-sha1"
      assert pattern.name == "Weak Cryptography - SHA1"
      assert pattern.description == "SHA1 is vulnerable to collision attacks"
      assert pattern.type == :weak_crypto
      assert pattern.severity == :medium
      assert pattern.languages == ["javascript", "typescript"]
      assert pattern.cwe_id == "CWE-328"
      assert pattern.owasp_category == "A02:2021"
      assert is_binary(pattern.recommendation)
      assert is_map(pattern.test_cases)
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
    end
    
    test "pattern detects vulnerable SHA1 usage" do
      pattern = WeakCryptoSha1.pattern()
      
      vulnerable_cases = [
        ~S|crypto.createHash('sha1')|,
        ~S|const hash = crypto.createHash("sha1").update(data).digest()|,
        ~S|crypto.createHash('SHA1')|,
        ~S|require('crypto').createHash('sha1')|,
        ~S|const hasher = crypto.createHash(`sha1`)|,
        ~S|import crypto from 'crypto'; crypto.createHash('sha1').digest('hex')|,
        ~S|const sha1Hash = crypto.createHash('SHA-1').update(password)|
      ]
      
      for code <- vulnerable_cases do
        assert Regex.match?(pattern.regex, code), 
          "Failed to match vulnerable code: #{code}"
      end
    end
    
    test "pattern does not match safe cryptographic usage" do
      pattern = WeakCryptoSha1.pattern()
      
      safe_cases = [
        ~S|crypto.createHash('sha256')|,
        ~S|crypto.createHash('sha3-256')|,
        ~S|const hash = crypto.createHash('sha512')|,
        ~S|crypto.createHash('blake2b512')|,
        ~S|await bcrypt.hash(password, 10)|,
        ~S|argon2.hash(password)|,
        ~S|scrypt(password, salt, 32)|,
        ~S|crypto.randomBytes(32)|,
        ~S|// This talks about sha1 but doesn't use it|,
        ~S|const comment = "sha1 is deprecated"| 
      ]
      
      for code <- safe_cases do
        refute Regex.match?(pattern.regex, code),
          "Incorrectly matched safe code: #{code}"
      end
    end
    
    test "vulnerability_metadata/0 returns comprehensive metadata" do
      metadata = WeakCryptoSha1.vulnerability_metadata()
      
      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert String.length(metadata.description) > 100
      
      # Check references structure
      assert is_list(metadata.references)
      assert length(metadata.references) >= 3
      
      for ref <- metadata.references do
        assert Map.has_key?(ref, :type)
        assert Map.has_key?(ref, :url)
        assert ref.type in [:cwe, :owasp, :research, :nist, :rfc]
        assert String.starts_with?(ref.url, "http")
      end
      
      # Check attack vectors
      assert is_list(metadata.attack_vectors)
      assert length(metadata.attack_vectors) >= 3
      
      # Check real world impact
      assert is_list(metadata.real_world_impact)
      assert length(metadata.real_world_impact) >= 3
      
      # Check CVE examples
      assert is_list(metadata.cve_examples)
      assert length(metadata.cve_examples) >= 2
      
      for cve <- metadata.cve_examples do
        assert Map.has_key?(cve, :id)
        assert Map.has_key?(cve, :description)
        assert Map.has_key?(cve, :severity)
        assert String.starts_with?(cve.id, "CVE-")
        assert cve.severity in ["low", "medium", "high", "critical"]
      end
      
      # Check safe alternatives
      assert is_list(metadata.safe_alternatives)
      assert length(metadata.safe_alternatives) >= 3
      
      # Check detection notes
      assert is_binary(metadata.detection_notes)
      assert String.length(metadata.detection_notes) > 50
    end
    
    test "applies_to_file?/1 works correctly" do
      # JavaScript and TypeScript files
      assert WeakCryptoSha1.applies_to_file?("test.js", nil)
      assert WeakCryptoSha1.applies_to_file?("app.jsx", nil)
      assert WeakCryptoSha1.applies_to_file?("server.ts", nil)
      assert WeakCryptoSha1.applies_to_file?("component.tsx", nil)
      assert WeakCryptoSha1.applies_to_file?("module.mjs", nil)
      
      # Non-JavaScript files
      refute WeakCryptoSha1.applies_to_file?("test.py", nil)
      refute WeakCryptoSha1.applies_to_file?("app.rb", nil)
      refute WeakCryptoSha1.applies_to_file?("server.php", nil)
    end
    
    test "applies_to_file?/2 detects embedded crypto operations" do
      # Should detect crypto operations in any file
      content_with_crypto = "const hash = crypto.createHash('sha1').digest('hex');"
      assert WeakCryptoSha1.applies_to_file?("template.html", content_with_crypto)
      
      # Should not match files without crypto operations
      content_without_crypto = "console.log('Hello world');"
      refute WeakCryptoSha1.applies_to_file?("template.html", content_without_crypto)
    end
    
    test "ast_enhancement/0 returns correct structure" do
      enhancement = WeakCryptoSha1.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      # Check AST rules
      assert is_map(enhancement.ast_rules)
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert is_map(enhancement.ast_rules.callee)
      
      # Check context rules
      assert is_map(enhancement.context_rules)
      assert is_list(enhancement.context_rules.exclude_paths)
      assert is_list(enhancement.context_rules.safe_alternatives)
      
      # Check confidence rules
      assert is_map(enhancement.confidence_rules)
      assert is_number(enhancement.confidence_rules.base)
      assert is_map(enhancement.confidence_rules.adjustments)
      
      # Check min confidence
      assert is_number(enhancement.min_confidence)
      assert enhancement.min_confidence >= 0.0
      assert enhancement.min_confidence <= 1.0
    end
    
    test "AST rules specify crypto.createHash patterns" do
      enhancement = WeakCryptoSha1.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert enhancement.ast_rules.callee.object == "crypto"
      assert enhancement.ast_rules.callee.property == "createHash"
      assert enhancement.ast_rules.algorithm_check == true
    end
    
    test "context rules exclude test files and check for legacy code" do
      enhancement = WeakCryptoSha1.ast_enhancement()
      
      # Should exclude test directories
      exclude_paths = enhancement.context_rules.exclude_paths
      assert Enum.any?(exclude_paths, &Regex.match?(&1, "test/"))
      assert Enum.any?(exclude_paths, &Regex.match?(&1, "spec/"))
      
      # Should check for legacy indicators
      assert enhancement.context_rules.check_legacy_markers == true
      assert is_list(enhancement.context_rules.legacy_indicators)
    end
    
    test "confidence scoring adjusts for context" do
      enhancement = WeakCryptoSha1.ast_enhancement()
      
      adjustments = enhancement.confidence_rules.adjustments
      
      # Should have positive adjustments for clear vulnerabilities
      assert adjustments["password_hashing"] > 0
      assert adjustments["security_context"] > 0
      
      # Should have negative adjustments for non-security usage
      assert adjustments["in_test_code"] < 0
      assert adjustments["git_sha_usage"] < 0
      assert adjustments["non_security_hash"] < 0
    end
  end
end