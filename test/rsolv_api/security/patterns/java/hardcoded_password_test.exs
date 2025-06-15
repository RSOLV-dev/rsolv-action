defmodule RsolvApi.Security.Patterns.Java.HardcodedPasswordTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Java.HardcodedPassword
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = HardcodedPassword.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "java-hardcoded-password"
      assert pattern.name == "Hardcoded Credentials"
      assert pattern.severity == :high
      assert pattern.type == :hardcoded_secret
      assert pattern.languages == ["java"]
      assert pattern.cwe_id == "CWE-798"
      assert pattern.owasp_category == "A07:2021"
      assert is_struct(pattern.regex, Regex) or is_list(pattern.regex)
      assert pattern.default_tier == :protected
    end
    
    test "includes comprehensive test cases" do
      pattern = HardcodedPassword.pattern()
      
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
      assert is_list(pattern.test_cases.vulnerable)
      assert is_list(pattern.test_cases.safe)
      assert length(pattern.test_cases.vulnerable) >= 2
      assert length(pattern.test_cases.safe) >= 2
    end
    
    test "has appropriate recommendation" do
      pattern = HardcodedPassword.pattern()
      
      assert String.contains?(String.downcase(pattern.recommendation), "environment") or
             String.contains?(String.downcase(pattern.recommendation), "configuration")
      assert String.contains?(String.downcase(pattern.recommendation), "password") or
             String.contains?(String.downcase(pattern.recommendation), "credential")
    end
  end
  
  describe "regex matching" do
    test "detects hardcoded password assignments" do
      pattern = HardcodedPassword.pattern()
      regex = if is_list(pattern.regex), do: hd(pattern.regex), else: pattern.regex
      
      vulnerable_code = [
        "String password = \"admin123\";",
        "private static final String PASSWORD = \"secretpass\";",
        "String pwd = \"mypassword\";",
        "final String passwd = \"defaultpwd\";",
        "String userPassword = \"password123\";",
        "private String dbPassword = \"databasepwd\";",
        "static String adminPassword = \"admin@2024\";"
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects hardcoded credentials in database connections" do
      pattern = HardcodedPassword.pattern()
      
      vulnerable_code = [
        "conn = DriverManager.getConnection(url, \"user\", \"passwd123\");",
        "ds.setPassword(\"hardcoded_password\");",
        "dataSource.setPassword(\"secret123\");",
        "Properties props = new Properties(); props.setProperty(\"password\", \"mysecret\");"
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects hardcoded API keys and tokens" do
      pattern = HardcodedPassword.pattern()
      
      vulnerable_code = [
        "String apiKey = \"sk-1234567890abcdef\";",
        "private static final String API_SECRET = \"secretkey123\";",
        "String authToken = \"Bearer abc123xyz789\";",
        "final String clientSecret = \"client_secret_value\";",
        "String accessToken = \"access_token_12345\";"
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects hardcoded credentials in authentication systems" do
      pattern = HardcodedPassword.pattern()
      
      vulnerable_code = [
        "if (username.equals(\"admin\") && password.equals(\"admin123\")) {",
        "String defaultPassword = \"changeme\";",
        "private static final String MASTER_PASSWORD = \"master@2024\";",
        "String servicePassword = \"service_account_pwd\";",
        "final String systemPassword = \"system123\";"
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects hardcoded encryption keys and secrets" do
      pattern = HardcodedPassword.pattern()
      
      vulnerable_code = [
        "String encryptionKey = \"mySecretKey123\";",
        "private static final String SECRET_KEY = \"encryption_secret\";",
        "String jwtSecret = \"jwt_signing_secret\";",
        "final String cryptoKey = \"crypto_key_value\";",
        "String hashSalt = \"hardcoded_salt_value\";"
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe credential handling" do
      pattern = HardcodedPassword.pattern()
      
      safe_code = [
        "String password = System.getenv(\"DB_PASSWORD\");",
        "String password = config.getString(\"database.password\");",
        "// String password = \"admin123\";",
        "String comment = \"Remember to set password\";",
        "String password = userInput.getPassword();",
        "String password = null;",
        "String password = \"\";",
        "String password = \"password\"; // Just a placeholder",
        "String passwordField = \"password_field_name\";"
      ]
      
      for code <- safe_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        refute Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should not match: #{code}"
      end
    end
    
    test "detects method parameters with hardcoded passwords" do
      pattern = HardcodedPassword.pattern()
      
      vulnerable_code = [
        "authenticate(\"admin\", \"password123\");",
        "login(username, \"hardcoded_password\");",
        "setCredentials(\"user\", \"secret123\");",
        "connect(\"server\", \"admin\", \"admin_password\");",
        "authorize(token, \"hardcoded_secret\");"
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects properties and configuration with hardcoded values" do
      pattern = HardcodedPassword.pattern()
      
      vulnerable_code = [
        "properties.setProperty(\"password\", \"secret123\");",
        "config.put(\"database.password\", \"db_password\");",
        "map.put(\"api.key\", \"hardcoded_api_key\");",
        "settings.setPassword(\"application_password\");",
        "params.addParameter(\"secret\", \"hardcoded_secret\");"
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = HardcodedPassword.vulnerability_metadata()
      
      assert String.contains?(String.downcase(metadata.description), "hardcoded") and
             String.contains?(String.downcase(metadata.description), "password")
      assert String.contains?(String.downcase(metadata.description), "credential")
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 4
      assert length(metadata.real_world_impact) >= 4
      assert length(metadata.cve_examples) >= 2
    end
    
    test "includes credential-specific information" do
      metadata = HardcodedPassword.vulnerability_metadata()
      
      assert String.contains?(metadata.description, "hardcoded") or String.contains?(metadata.description, "password")
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "environment")) or
             Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "configuration"))
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "management")) or
             Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "secure"))
    end
    
    test "includes proper security references" do
      metadata = HardcodedPassword.vulnerability_metadata()
      
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
    
    test "includes OWASP Top 10 information" do
      metadata = HardcodedPassword.vulnerability_metadata()
      
      assert Enum.any?(metadata.references, fn ref ->
        String.contains?(String.downcase(ref.title), "owasp") and 
        String.contains?(String.downcase(ref.title), "a07")
      end)
    end
    
    test "includes CVE examples with proper structure" do
      metadata = HardcodedPassword.vulnerability_metadata()
      
      for cve <- metadata.cve_examples do
        assert Map.has_key?(cve, :id)
        assert Map.has_key?(cve, :description)
        assert Map.has_key?(cve, :severity)
        assert Map.has_key?(cve, :cvss)
        assert is_number(cve.cvss)
        assert cve.cvss > 0
      end
    end
    
    test "includes credential-specific attack information" do
      metadata = HardcodedPassword.vulnerability_metadata()
      
      assert Enum.any?(metadata.additional_context.secure_patterns, fn pattern ->
        String.contains?(String.downcase(pattern), "environment") or
        String.contains?(String.downcase(pattern), "configuration") or
        String.contains?(String.downcase(pattern), "vault")
      end)
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = HardcodedPassword.ast_enhancement()
      
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.7
    end
    
    test "includes credential analysis" do
      enhancement = HardcodedPassword.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "AssignmentExpression" or
             enhancement.ast_rules.node_type == "VariableDeclaration"
      assert enhancement.ast_rules.credential_analysis.check_hardcoded_values
      assert enhancement.ast_rules.credential_analysis.credential_patterns
      assert enhancement.ast_rules.credential_analysis.check_string_literals
    end
    
    test "has authentication context detection rules" do
      enhancement = HardcodedPassword.ast_enhancement()
      
      assert enhancement.ast_rules.auth_analysis.check_authentication_context
      assert enhancement.ast_rules.auth_analysis.method_patterns
      assert enhancement.ast_rules.auth_analysis.dangerous_assignments
    end
    
    test "includes configuration analysis" do
      enhancement = HardcodedPassword.ast_enhancement()
      
      assert enhancement.ast_rules.config_analysis.check_configuration_files
      assert enhancement.ast_rules.config_analysis.property_patterns
      assert enhancement.ast_rules.config_analysis.dangerous_configurations
    end
    
    test "includes API key analysis" do
      enhancement = HardcodedPassword.ast_enhancement()
      
      assert enhancement.ast_rules.api_analysis.check_api_credentials
      assert enhancement.ast_rules.api_analysis.api_key_patterns
      assert enhancement.ast_rules.api_analysis.token_patterns
    end
    
    test "includes context-based filtering" do
      enhancement = HardcodedPassword.ast_enhancement()
      
      assert enhancement.context_rules.check_environment_usage
      assert enhancement.context_rules.safe_credential_sources
      assert enhancement.context_rules.hardcoded_credential_indicators
    end
    
    test "has proper confidence scoring" do
      enhancement = HardcodedPassword.ast_enhancement()
      
      adjustments = enhancement.confidence_rules.adjustments
      assert Map.has_key?(adjustments, "uses_environment_variables")
      assert Map.has_key?(adjustments, "uses_configuration_management")
      assert Map.has_key?(adjustments, "in_authentication_context")
      assert Map.has_key?(adjustments, "in_test_code")
    end
  end
end