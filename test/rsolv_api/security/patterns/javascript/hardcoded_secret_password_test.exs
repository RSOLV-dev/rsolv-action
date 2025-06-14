defmodule RsolvApi.Security.Patterns.Javascript.HardcodedSecretPasswordTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Javascript.HardcodedSecretPassword
  alias RsolvApi.Security.Pattern
  
  describe "HardcodedSecretPassword pattern" do
    test "pattern/0 returns correct structure" do
      pattern = HardcodedSecretPassword.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-hardcoded-secret-password"
      assert pattern.name == "Hardcoded Password"
      assert pattern.description == "Passwords should never be hardcoded in source code"
      assert pattern.type == :hardcoded_secret
      assert pattern.severity == :high
      assert pattern.languages == ["javascript", "typescript"]
      assert pattern.default_tier == :public
      assert pattern.cwe_id == "CWE-798"
      assert pattern.owasp_category == "A07:2021"
      assert is_binary(pattern.recommendation)
      assert is_map(pattern.test_cases)
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
    end
    
    test "pattern detects vulnerable hardcoded password usage" do
      pattern = HardcodedSecretPassword.pattern()
      
      vulnerable_cases = [
        ~s(const password = "admin123"),
        ~s(let dbPassword = 'secretpass'),
        ~s(var config = { password: "mysecret123" }),
        ~s(const PASSWORD = "P@ssw0rd!"),
        ~s(let userPassword = `superSecret2024`),
        ~s(var auth = { passwd: "test1234" }),
        ~s(const pwd = "quickPass"),
        ~s(password: "defaultPassword"),
        ~s(const dbConfig = { password: "root123" }),
        ~s(let credentials = { pwd: "admin@2024" })
      ]
      
      for code <- vulnerable_cases do
        assert Regex.match?(pattern.regex, code), 
          "Failed to match vulnerable code: #{code}"
      end
    end
    
    test "pattern does not match safe password handling" do
      pattern = HardcodedSecretPassword.pattern()
      
      safe_cases = [
        ~S|const password = process.env.DB_PASSWORD|,
        ~S|const password = config.get('database.password')|,
        ~S|const password = await secretManager.getSecret('db-password')|,
        ~S|let password = getPasswordFromVault()|,
        ~S|const pwd = getUserInput()|,
        ~S|var password = prompt("Enter password:")|,
        ~S|password = await hashPassword(userInput)|,
        ~S|const hashedPassword = bcrypt.hash(plaintext, 10)|,
        ~S|// password should be stored securely|,
        ~S|const validationMessage = "password must contain uppercase"|,
        ~S|const passwordField = document.getElementById("password")|,
        ~S|function validatePassword(pwd) { return pwd.length > 8; }|,
        ~S|const passwordRegex = /^(?=.*[A-Z])(?=.*[a-z])/|,
        ~S|console.log("Password validation failed")|
      ]
      
      for code <- safe_cases do
        refute Regex.match?(pattern.regex, code),
          "Incorrectly matched safe code: #{code}"
      end
    end
    
    test "vulnerability_metadata/0 returns comprehensive metadata" do
      metadata = HardcodedSecretPassword.vulnerability_metadata()
      
      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert String.length(metadata.description) > 100
      
      # Check references structure
      assert is_list(metadata.references)
      assert length(metadata.references) >= 3
      
      for ref <- metadata.references do
        assert Map.has_key?(ref, :type)
        assert Map.has_key?(ref, :url)
        assert ref.type in [:cwe, :owasp, :nist, :research, :sans]
        assert String.starts_with?(ref.url, "http")
      end
      
      # Check attack vectors
      assert is_list(metadata.attack_vectors)
      assert length(metadata.attack_vectors) >= 4
      
      # Check real world impact
      assert is_list(metadata.real_world_impact)
      assert length(metadata.real_world_impact) >= 4
      
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
      assert length(metadata.safe_alternatives) >= 4
      
      # Check detection notes
      assert is_binary(metadata.detection_notes)
      assert String.length(metadata.detection_notes) > 50
    end
    
    test "applies_to_file?/1 works correctly" do
      # JavaScript and TypeScript files
      assert HardcodedSecretPassword.applies_to_file?("test.js")
      assert HardcodedSecretPassword.applies_to_file?("app.jsx")
      assert HardcodedSecretPassword.applies_to_file?("server.ts")
      assert HardcodedSecretPassword.applies_to_file?("component.tsx")
      assert HardcodedSecretPassword.applies_to_file?("module.mjs")
      
      # Non-JavaScript files
      refute HardcodedSecretPassword.applies_to_file?("test.py")
      refute HardcodedSecretPassword.applies_to_file?("app.rb")
      refute HardcodedSecretPassword.applies_to_file?("server.php")
    end
    
    test "applies_to_file?/2 detects embedded password assignments" do
      # Should detect password assignments in any file
      content_with_password = ~s(const dbPassword = "secretPassword123";)
      assert HardcodedSecretPassword.applies_to_file?("config.json", content_with_password)
      
      # Should not match files without password assignments
      content_without_password = ~s(const apiUrl = "https://api.example.com";)
      refute HardcodedSecretPassword.applies_to_file?("config.json", content_without_password)
    end
    
    test "ast_enhancement/0 returns correct structure" do
      enhancement = HardcodedSecretPassword.ast_enhancement()
      
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
    
    test "AST rules specify variable assignment patterns" do
      enhancement = HardcodedSecretPassword.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "VariableDeclarator"
      assert "Literal" in enhancement.ast_rules.value_types
      assert is_map(enhancement.ast_rules.identifier_check)
      assert Regex.match?(enhancement.ast_rules.identifier_check.pattern, "password")
    end
    
    test "context rules exclude test files and check for safe patterns" do
      enhancement = HardcodedSecretPassword.ast_enhancement()
      
      # Should exclude test directories
      exclude_paths = enhancement.context_rules.exclude_paths
      assert Enum.any?(exclude_paths, &Regex.match?(&1, "test/"))
      assert Enum.any?(exclude_paths, &Regex.match?(&1, "spec/"))
      
      # Should have safe patterns
      assert is_list(enhancement.context_rules.safe_patterns)
      assert "process.env" in enhancement.context_rules.safe_patterns
      assert "getenv" in enhancement.context_rules.safe_patterns
    end
    
    test "confidence scoring adjusts for context" do
      enhancement = HardcodedSecretPassword.ast_enhancement()
      
      adjustments = enhancement.confidence_rules.adjustments
      
      # Should have positive adjustments for clear vulnerabilities
      assert adjustments["literal_string_value"] > 0
      assert adjustments["production_file"] > 0
      
      # Should have negative adjustments for safe patterns
      assert adjustments["environment_variable"] < 0
      assert adjustments["test_file"] < 0
      assert adjustments["example_code"] < 0
    end
  end
end