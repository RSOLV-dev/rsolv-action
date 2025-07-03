defmodule Rsolv.Security.Patterns.Java.WeakHashMd5Test do
  use ExUnit.Case, async: true
  
  alias Rsolv.Security.Patterns.Java.WeakHashMd5
  alias Rsolv.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = WeakHashMd5.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "java-weak-hash-md5"
      assert pattern.name == "Weak Cryptography - MD5"
      assert pattern.severity == :medium
      assert pattern.type == :weak_crypto
      assert pattern.languages == ["java"]
      assert pattern.cwe_id == "CWE-327"
      assert pattern.owasp_category == "A02:2021"
      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 3
      assert Enum.all?(pattern.regex, &is_struct(&1, Regex))
    end
    
    test "includes comprehensive test cases" do
      pattern = WeakHashMd5.pattern()
      
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
      assert is_list(pattern.test_cases.vulnerable)
      assert is_list(pattern.test_cases.safe)
      assert length(pattern.test_cases.vulnerable) >= 2
      assert length(pattern.test_cases.safe) >= 2
    end
    
    test "has appropriate recommendation" do
      pattern = WeakHashMd5.pattern()
      
      assert String.contains?(String.downcase(pattern.recommendation), "sha") or
             String.contains?(String.downcase(pattern.recommendation), "secure")
      assert String.contains?(String.downcase(pattern.recommendation), "hash") or
             String.contains?(String.downcase(pattern.recommendation), "digest")
    end
  end
  
  describe "regex matching" do
    test "detects MessageDigest.getInstance with MD5" do
      pattern = WeakHashMd5.pattern()
      
      vulnerable_code = [
        "MessageDigest md = MessageDigest.getInstance(\"MD5\");",
        "MessageDigest.getInstance(\"MD5\").digest(password.getBytes());",
        "MessageDigest messageDigest = MessageDigest.getInstance(\"MD5\");",
        "digest = MessageDigest.getInstance(\"MD5\");",
        "MessageDigest md5 = MessageDigest.getInstance(\"MD5\");",
        "MessageDigest hash = MessageDigest.getInstance(\"MD5\");",
        "MessageDigest.getInstance(\"MD5\").update(data);"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects MD5 in various contexts" do
      pattern = WeakHashMd5.pattern()
      
      vulnerable_code = [
        "private static final String ALGORITHM = \"MD5\";",
        "if (algorithm.equals(\"MD5\")) {",
        "String hashType = \"MD5\";",
        "return createHash(\"MD5\", data);",
        "digestAlgorithm = \"MD5\";",
        "getDigest(\"MD5\");"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects MD5 with different quotes and spacing" do
      pattern = WeakHashMd5.pattern()
      
      vulnerable_code = [
        "MessageDigest.getInstance( \"MD5\" );",
        "MessageDigest.getInstance('MD5');",
        "getInstance(  \"MD5\"  );",
        "MessageDigest.getInstance(\"MD5\")",
        ".getInstance(\"MD5\").",
        "MessageDigest md=MessageDigest.getInstance(\"MD5\");"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe hash algorithms" do
      pattern = WeakHashMd5.pattern()
      
      safe_code = [
        "MessageDigest md = MessageDigest.getInstance(\"SHA-256\");",
        "MessageDigest.getInstance(\"SHA-512\").digest(data);",
        "MessageDigest sha3 = MessageDigest.getInstance(\"SHA3-256\");",
        "String algorithm = \"SHA-256\";",
        "// Using MD5 for backwards compatibility",
        "// MessageDigest.getInstance(\"MD5\");",
        "BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();",
        "MessageDigest.getInstance(\"SHA-1\");",
        "String filename = \"document.md5\";",
        "if (!md5Hash.isEmpty()) {"
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should not match: #{code}"
      end
    end
    
    test "detects MD5 in method names and assignments" do
      pattern = WeakHashMd5.pattern()
      
      vulnerable_code = [
        "public String computeMD5(String input) {",
        "private String generateMD5Hash(byte[] data) {",
        "return calculateMD5(password);",
        "String hash = getMD5Digest(data);",
        "md5Hash = computeHash(\"MD5\", input);",
        "hashAlgorithm = HashAlgorithm.MD5;"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = WeakHashMd5.vulnerability_metadata()
      
      assert String.contains?(String.downcase(metadata.description), "md5")
      assert String.contains?(String.downcase(metadata.description), "collision")
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 4
      assert length(metadata.real_world_impact) >= 4
      assert length(metadata.cve_examples) >= 2
    end
    
    test "includes MD5-specific information" do
      metadata = WeakHashMd5.vulnerability_metadata()
      
      assert String.contains?(metadata.description, "MD5")
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "SHA-256"))
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "SHA-3"))
    end
    
    test "includes proper security references" do
      metadata = WeakHashMd5.vulnerability_metadata()
      
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
    
    test "includes collision attack vectors" do
      metadata = WeakHashMd5.vulnerability_metadata()
      
      assert Enum.any?(metadata.attack_vectors, &String.contains?(&1, "collision"))
      assert Enum.any?(metadata.attack_vectors, &String.contains?(&1, "certificate"))
    end
    
    test "includes CVE examples with proper structure" do
      metadata = WeakHashMd5.vulnerability_metadata()
      
      for cve <- metadata.cve_examples do
        assert Map.has_key?(cve, :id)
        assert Map.has_key?(cve, :description)
        assert Map.has_key?(cve, :severity)
        assert Map.has_key?(cve, :cvss)
        assert is_number(cve.cvss)
        assert cve.cvss > 0
      end
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = WeakHashMd5.ast_enhancement()
      
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.6
    end
    
    test "includes MessageDigest analysis" do
      enhancement = WeakHashMd5.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "MethodInvocation"
      assert enhancement.ast_rules.crypto_analysis.check_algorithm_parameter
      assert enhancement.ast_rules.crypto_analysis.weak_algorithms
      assert enhancement.ast_rules.crypto_analysis.check_method_name
    end
    
    test "has algorithm detection rules" do
      enhancement = WeakHashMd5.ast_enhancement()
      
      assert enhancement.ast_rules.algorithm_detection.check_string_literals
      assert enhancement.ast_rules.algorithm_detection.weak_algorithm_patterns
      assert enhancement.ast_rules.algorithm_detection.check_variable_assignments
    end
    
    test "includes context-based filtering" do
      enhancement = WeakHashMd5.ast_enhancement()
      
      assert enhancement.context_rules.check_cryptographic_context
      assert enhancement.context_rules.acceptable_uses
      assert enhancement.context_rules.strong_algorithms
    end
    
    test "has proper confidence scoring" do
      enhancement = WeakHashMd5.ast_enhancement()
      
      adjustments = enhancement.confidence_rules.adjustments
      assert Map.has_key?(adjustments, "is_cryptographic_context")
      assert Map.has_key?(adjustments, "has_security_variable_name")
      assert Map.has_key?(adjustments, "uses_checksum_only")
      assert Map.has_key?(adjustments, "in_test_code")
    end
  end
end