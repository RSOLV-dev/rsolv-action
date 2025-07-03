defmodule Rsolv.Security.Patterns.Java.WeakHashSha1Test do
  use ExUnit.Case, async: true
  
  alias Rsolv.Security.Patterns.Java.WeakHashSha1
  alias Rsolv.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = WeakHashSha1.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "java-weak-hash-sha1"
      assert pattern.name == "Weak Cryptography - SHA1"
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
      pattern = WeakHashSha1.pattern()
      
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
      assert is_list(pattern.test_cases.vulnerable)
      assert is_list(pattern.test_cases.safe)
      assert length(pattern.test_cases.vulnerable) >= 2
      assert length(pattern.test_cases.safe) >= 2
    end
    
    test "has appropriate recommendation" do
      pattern = WeakHashSha1.pattern()
      
      assert String.contains?(String.downcase(pattern.recommendation), "sha") and
             String.contains?(String.downcase(pattern.recommendation), "256")
      assert String.contains?(String.downcase(pattern.recommendation), "secure") or
             String.contains?(String.downcase(pattern.recommendation), "strong")
    end
  end
  
  describe "regex matching" do
    test "detects MessageDigest.getInstance with SHA-1" do
      pattern = WeakHashSha1.pattern()
      
      vulnerable_code = [
        "MessageDigest md = MessageDigest.getInstance(\"SHA-1\");",
        "MessageDigest.getInstance(\"SHA-1\").digest(password.getBytes());",
        "MessageDigest messageDigest = MessageDigest.getInstance(\"SHA-1\");",
        "digest = MessageDigest.getInstance(\"SHA-1\");",
        "MessageDigest sha1 = MessageDigest.getInstance(\"SHA-1\");",
        "MessageDigest hash = MessageDigest.getInstance(\"SHA-1\");",
        "MessageDigest.getInstance(\"SHA-1\").update(data);"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects SHA-1 in various contexts" do
      pattern = WeakHashSha1.pattern()
      
      vulnerable_code = [
        "private static final String ALGORITHM = \"SHA-1\";",
        "if (algorithm.equals(\"SHA-1\")) {",
        "String hashType = \"SHA-1\";",
        "return createHash(\"SHA-1\", data);",
        "digestAlgorithm = \"SHA-1\";",
        "getDigest(\"SHA-1\");",
        "private static final String SHA1_ALGORITHM = \"SHA-1\";",
        "hashMap.put(\"algorithm\", \"SHA-1\");"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects SHA-1 with different quotes and spacing" do
      pattern = WeakHashSha1.pattern()
      
      vulnerable_code = [
        "MessageDigest.getInstance( \"SHA-1\" );",
        "MessageDigest.getInstance('SHA-1');",
        "getInstance(  \"SHA-1\"  );",
        "MessageDigest.getInstance(\"SHA-1\")",
        ".getInstance(\"SHA-1\").",
        "MessageDigest md=MessageDigest.getInstance(\"SHA-1\");"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects SHA-1 method names and variable assignments" do
      pattern = WeakHashSha1.pattern()
      
      vulnerable_code = [
        "public String computeSHA1(String input) {",
        "private String generateSHA1Hash(byte[] data) {",
        "return calculateSHA1(password);",
        "String hash = getSHA1Digest(data);",
        "sha1Hash = computeHash(\"SHA-1\", input);",
        "hashAlgorithm = HashAlgorithm.SHA1;",
        "digestType = DigestType.SHA_1;"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe hash algorithms" do
      pattern = WeakHashSha1.pattern()
      
      safe_code = [
        "MessageDigest md = MessageDigest.getInstance(\"SHA-256\");",
        "MessageDigest.getInstance(\"SHA-512\").digest(data);",
        "MessageDigest sha3 = MessageDigest.getInstance(\"SHA3-256\");",
        "String algorithm = \"SHA-256\";",
        "// Using SHA-1 for backwards compatibility",
        "// MessageDigest.getInstance(\"SHA-1\");",
        "BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();",
        "MessageDigest.getInstance(\"MD5\");",
        "String filename = \"document.sha1\";",
        "if (!sha1Hash.isEmpty()) {"
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should not match: #{code}"
      end
    end
    
    test "detects SHA-1 in TLS and certificate contexts" do
      pattern = WeakHashSha1.pattern()
      
      vulnerable_code = [
        "signatureAlgorithm = \"SHA1withRSA\";",
        "signature.initSign(privateKey, \"SHA1withRSA\");",
        "cert.verify(publicKey, \"SHA1withRSA\");",
        "KeyPairGenerator.getInstance(\"RSA\").initialize(2048, \"SHA1PRNG\");",
        "SecureRandom.getInstance(\"SHA1PRNG\");",
        "sslContext.init(null, null, SecureRandom.getInstance(\"SHA1PRNG\"));"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = WeakHashSha1.vulnerability_metadata()
      
      assert String.contains?(String.downcase(metadata.description), "sha-1")
      assert String.contains?(String.downcase(metadata.description), "collision") or
             String.contains?(String.downcase(metadata.description), "deprecated")
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 4
      assert length(metadata.real_world_impact) >= 4
      assert length(metadata.cve_examples) >= 2
    end
    
    test "includes SHA-1-specific information" do
      metadata = WeakHashSha1.vulnerability_metadata()
      
      assert String.contains?(metadata.description, "SHA-1")
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "SHA-256"))
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "SHA-3"))
    end
    
    test "includes proper security references" do
      metadata = WeakHashSha1.vulnerability_metadata()
      
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
    
    test "includes SLOTH attack information" do
      metadata = WeakHashSha1.vulnerability_metadata()
      
      assert Enum.any?(metadata.attack_vectors, fn vector -> 
        String.contains?(String.downcase(vector), "sloth") or
        String.contains?(String.downcase(vector), "tls") or
        String.contains?(String.downcase(vector), "collision")
      end)
    end
    
    test "includes CVE examples with proper structure" do
      metadata = WeakHashSha1.vulnerability_metadata()
      
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
      enhancement = WeakHashSha1.ast_enhancement()
      
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.6
    end
    
    test "includes MessageDigest analysis" do
      enhancement = WeakHashSha1.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "MethodInvocation"
      assert enhancement.ast_rules.crypto_analysis.check_algorithm_parameter
      assert enhancement.ast_rules.crypto_analysis.weak_algorithms
      assert enhancement.ast_rules.crypto_analysis.check_method_name
    end
    
    test "has algorithm detection rules" do
      enhancement = WeakHashSha1.ast_enhancement()
      
      assert enhancement.ast_rules.algorithm_detection.check_string_literals
      assert enhancement.ast_rules.algorithm_detection.weak_algorithm_patterns
      assert enhancement.ast_rules.algorithm_detection.check_variable_assignments
    end
    
    test "includes TLS and signature context detection" do
      enhancement = WeakHashSha1.ast_enhancement()
      
      assert enhancement.ast_rules.signature_analysis.check_signature_algorithms
      assert enhancement.ast_rules.signature_analysis.weak_signature_patterns
      assert enhancement.ast_rules.signature_analysis.check_tls_contexts
    end
    
    test "includes context-based filtering" do
      enhancement = WeakHashSha1.ast_enhancement()
      
      assert enhancement.context_rules.check_cryptographic_context
      assert enhancement.context_rules.acceptable_uses
      assert enhancement.context_rules.strong_algorithms
    end
    
    test "has proper confidence scoring" do
      enhancement = WeakHashSha1.ast_enhancement()
      
      adjustments = enhancement.confidence_rules.adjustments
      assert Map.has_key?(adjustments, "is_cryptographic_context")
      assert Map.has_key?(adjustments, "has_security_variable_name")
      assert Map.has_key?(adjustments, "in_tls_context")
      assert Map.has_key?(adjustments, "in_test_code")
    end
  end
end