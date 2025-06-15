defmodule RsolvApi.Security.Patterns.Java.WeakCipherDesTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Java.WeakCipherDes
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = WeakCipherDes.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "java-weak-cipher-des"
      assert pattern.name == "Weak Cryptography - DES"
      assert pattern.severity == :high
      assert pattern.type == :weak_crypto
      assert pattern.languages == ["java"]
      assert pattern.cwe_id == "CWE-327"
      assert pattern.owasp_category == "A02:2021"
      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 4
      assert Enum.all?(pattern.regex, &is_struct(&1, Regex))
      assert pattern.default_tier == :public
    end
    
    test "includes comprehensive test cases" do
      pattern = WeakCipherDes.pattern()
      
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
      assert is_list(pattern.test_cases.vulnerable)
      assert is_list(pattern.test_cases.safe)
      assert length(pattern.test_cases.vulnerable) >= 2
      assert length(pattern.test_cases.safe) >= 2
    end
    
    test "has appropriate recommendation" do
      pattern = WeakCipherDes.pattern()
      
      assert String.contains?(String.downcase(pattern.recommendation), "aes") 
      assert String.contains?(String.downcase(pattern.recommendation), "256") or
             String.contains?(String.downcase(pattern.recommendation), "modern")
    end
  end
  
  describe "regex matching" do
    test "detects Cipher.getInstance with DES" do
      pattern = WeakCipherDes.pattern()
      
      vulnerable_code = [
        "Cipher cipher = Cipher.getInstance(\"DES\");",
        "Cipher.getInstance(\"DES\").init(Cipher.ENCRYPT_MODE, key);",
        "Cipher desCipher = Cipher.getInstance(\"DES\");",
        "cipher = Cipher.getInstance(\"DES\");",
        "Cipher enc = Cipher.getInstance(\"DES\");",
        "Cipher.getInstance(\"DES/ECB/PKCS5Padding\");",
        "Cipher.getInstance(\"DES/CBC/PKCS5Padding\");"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects DES with different modes and padding" do
      pattern = WeakCipherDes.pattern()
      
      vulnerable_code = [
        "Cipher.getInstance(\"DES/ECB/NoPadding\");",
        "Cipher.getInstance(\"DES/CBC/ISO10126Padding\");",
        "Cipher.getInstance(\"DES/CFB/PKCS5Padding\");",
        "Cipher.getInstance(\"DES/OFB/NoPadding\");",
        "String algorithm = \"DES/ECB/PKCS5Padding\";",
        "cipher.init(Cipher.ENCRYPT_MODE, key, \"DES\");",
        "new SecretKeySpec(keyBytes, \"DES\");"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects Triple DES and 3DES variants" do
      pattern = WeakCipherDes.pattern()
      
      vulnerable_code = [
        "Cipher.getInstance(\"DESede\");",
        "Cipher.getInstance(\"TripleDES\");",
        "Cipher.getInstance(\"3DES\");",
        "Cipher.getInstance(\"DESede/ECB/PKCS5Padding\");",
        "new SecretKeySpec(keyBytes, \"DESede\");",
        "new SecretKeySpec(key, \"TripleDES\");",
        "KeyGenerator.getInstance(\"DESede\");"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects DES with various quotes and spacing" do
      pattern = WeakCipherDes.pattern()
      
      vulnerable_code = [
        "Cipher.getInstance( \"DES\" );",
        "Cipher.getInstance('DES');",
        "getInstance(  \"DES\"  );",
        "Cipher.getInstance(\"DES\")",
        ".getInstance(\"DESede\").",
        "Cipher enc=Cipher.getInstance(\"DES\");",
        "getInstance(\"DES/ECB/PKCS5Padding\" );"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects DES variable assignments and constants" do
      pattern = WeakCipherDes.pattern()
      
      vulnerable_code = [
        "private static final String ALGORITHM = \"DES\";",
        "String cipherAlgorithm = \"DES\";",
        "algorithm = \"DESede\";",
        "String transformation = \"DES/ECB/PKCS5Padding\";",
        "final String CIPHER_TYPE = \"TripleDES\";",
        "String encryptionMethod = \"3DES\";",
        "public static final String DES_ALGORITHM = \"DES\";"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe cipher algorithms" do
      pattern = WeakCipherDes.pattern()
      
      safe_code = [
        "Cipher cipher = Cipher.getInstance(\"AES\");",
        "Cipher.getInstance(\"AES/GCM/NoPadding\").init(mode, key);",
        "Cipher aesCipher = Cipher.getInstance(\"AES/CBC/PKCS5Padding\");",
        "String algorithm = \"AES-256\";",
        "// Using DES for backwards compatibility",
        "// Cipher.getInstance(\"DES\");",
        "ChaCha20Poly1305 cipher = new ChaCha20Poly1305();",
        "Cipher.getInstance(\"RSA\");",
        "String filename = \"design.des\";",
        "String description = \"DES encryption is deprecated\";"
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should not match: #{code}"
      end
    end
    
    test "detects KeyGenerator and SecretKeySpec with DES" do
      pattern = WeakCipherDes.pattern()
      
      vulnerable_code = [
        "KeyGenerator keyGen = KeyGenerator.getInstance(\"DES\");",
        "KeyGenerator.getInstance(\"DESede\").generateKey();",
        "SecretKeySpec keySpec = new SecretKeySpec(bytes, \"DES\");",
        "new SecretKeySpec(keyData, \"TripleDES\");",
        "SecretKey key = new SecretKeySpec(keyBytes, \"DESede\");",
        "keyFactory.getInstance(\"DES\");",
        "SecretKeyFactory.getInstance(\"DESede\");"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = WeakCipherDes.vulnerability_metadata()
      
      assert String.contains?(String.downcase(metadata.description), "des")
      assert String.contains?(String.downcase(metadata.description), "56-bit") or
             String.contains?(String.downcase(metadata.description), "weak")
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 4
      assert length(metadata.real_world_impact) >= 4
      assert length(metadata.cve_examples) >= 2
    end
    
    test "includes DES-specific information" do
      metadata = WeakCipherDes.vulnerability_metadata()
      
      assert String.contains?(metadata.description, "DES") or String.contains?(metadata.description, "Data Encryption Standard")
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "AES"))
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "256")) or
             Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "GCM"))
    end
    
    test "includes proper security references" do
      metadata = WeakCipherDes.vulnerability_metadata()
      
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
    
    test "includes Sweet32 attack information" do
      metadata = WeakCipherDes.vulnerability_metadata()
      
      assert Enum.any?(metadata.attack_vectors, fn vector -> 
        String.contains?(String.downcase(vector), "sweet32") or
        String.contains?(String.downcase(vector), "birthday") or
        String.contains?(String.downcase(vector), "64-bit")
      end)
    end
    
    test "includes CVE examples with proper structure" do
      metadata = WeakCipherDes.vulnerability_metadata()
      
      for cve <- metadata.cve_examples do
        assert Map.has_key?(cve, :id)
        assert Map.has_key?(cve, :description)
        assert Map.has_key?(cve, :severity)
        assert Map.has_key?(cve, :cvss)
        assert is_number(cve.cvss)
        assert cve.cvss > 0
      end
    end
    
    test "includes 3DES deprecation information" do
      metadata = WeakCipherDes.vulnerability_metadata()
      
      assert Enum.any?(metadata.additional_context.compliance_considerations, fn note ->
        String.contains?(String.downcase(note), "3des") or
        String.contains?(String.downcase(note), "triple") or
        String.contains?(String.downcase(note), "nist")
      end)
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = WeakCipherDes.ast_enhancement()
      
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.6
    end
    
    test "includes Cipher analysis" do
      enhancement = WeakCipherDes.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "MethodInvocation"
      assert enhancement.ast_rules.cipher_analysis.check_algorithm_parameter
      assert enhancement.ast_rules.cipher_analysis.weak_algorithms
      assert enhancement.ast_rules.cipher_analysis.check_method_name
    end
    
    test "has algorithm detection rules" do
      enhancement = WeakCipherDes.ast_enhancement()
      
      assert enhancement.ast_rules.algorithm_detection.check_string_literals
      assert enhancement.ast_rules.algorithm_detection.weak_algorithm_patterns
      assert enhancement.ast_rules.algorithm_detection.check_variable_assignments
    end
    
    test "includes key generation analysis" do
      enhancement = WeakCipherDes.ast_enhancement()
      
      assert enhancement.ast_rules.key_analysis.check_key_generation
      assert enhancement.ast_rules.key_analysis.weak_key_algorithms
      assert enhancement.ast_rules.key_analysis.check_secret_key_spec
    end
    
    test "includes context-based filtering" do
      enhancement = WeakCipherDes.ast_enhancement()
      
      assert enhancement.context_rules.check_cryptographic_context
      assert enhancement.context_rules.deprecated_algorithms
      assert enhancement.context_rules.strong_algorithms
    end
    
    test "has proper confidence scoring" do
      enhancement = WeakCipherDes.ast_enhancement()
      
      adjustments = enhancement.confidence_rules.adjustments
      assert Map.has_key?(adjustments, "is_cryptographic_context")
      assert Map.has_key?(adjustments, "has_security_variable_name")
      assert Map.has_key?(adjustments, "uses_weak_mode")
      assert Map.has_key?(adjustments, "in_test_code")
    end
  end
end