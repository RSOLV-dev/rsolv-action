defmodule RsolvApi.Security.Patterns.Java.WeakRandomTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Java.WeakRandom
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = WeakRandom.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "java-weak-random"
      assert pattern.name == "Weak Random Number Generation"
      assert pattern.severity == :medium
      assert pattern.type == :insecure_random
      assert pattern.languages == ["java"]
      assert pattern.cwe_id == "CWE-338"
      assert pattern.owasp_category == "A02:2021"
      assert is_struct(pattern.regex, Regex) or is_list(pattern.regex)
      assert pattern.default_tier == :ai
    end
    
    test "includes comprehensive test cases" do
      pattern = WeakRandom.pattern()
      
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
      assert is_list(pattern.test_cases.vulnerable)
      assert is_list(pattern.test_cases.safe)
      assert length(pattern.test_cases.vulnerable) >= 2
      assert length(pattern.test_cases.safe) >= 2
    end
    
    test "has appropriate recommendation" do
      pattern = WeakRandom.pattern()
      
      assert String.contains?(String.downcase(pattern.recommendation), "securerandom") or
             String.contains?(String.downcase(pattern.recommendation), "cryptographically")
      assert String.contains?(String.downcase(pattern.recommendation), "random")
    end
  end
  
  describe "regex matching" do
    test "detects java.util.Random instantiation" do
      pattern = WeakRandom.pattern()
      
      vulnerable_code = [
        "Random rand = new Random();",
        "Random random = new Random(System.currentTimeMillis());",
        "private Random rng = new Random();",
        "final Random generator = new Random(12345);",
        "Random randomGenerator = new Random(seed);",
        "public Random randomInstance = new Random();",
        "static Random staticRandom = new Random();"
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects Math.random() usage" do
      pattern = WeakRandom.pattern()
      
      vulnerable_code = [
        "double random = Math.random();",
        "int value = (int) (Math.random() * 100);",
        "float randomFloat = (float) Math.random();",
        "return Math.random() * range;",
        "if (Math.random() > 0.5) {",
        "double[] randoms = {Math.random(), Math.random()};",
        "System.out.println(Math.random());"
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects Random method calls for security purposes" do
      pattern = WeakRandom.pattern()
      
      vulnerable_code = [
        "int token = random.nextInt(1000000);",
        "String sessionId = String.valueOf(random.nextLong());",
        "byte[] bytes = new byte[16]; random.nextBytes(bytes);",
        "double authValue = random.nextDouble();",
        "boolean decision = random.nextBoolean();",
        "float securityFloat = random.nextFloat();",
        "long userId = random.nextLong();"
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects Random usage in token generation contexts" do
      pattern = WeakRandom.pattern()
      
      vulnerable_code = [
        "String passwordResetToken = generateToken(new Random());",
        "String apiKey = createApiKey(random);",
        "UUID sessionId = UUID.fromString(random.nextInt() + \"\");",
        "String csrfToken = randomString(random, 32);",
        "int verificationCode = random.nextInt(999999);",
        "String otp = String.format(\"%06d\", random.nextInt(1000000));",
        "byte[] salt = generateSalt(random);"
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects ThreadLocalRandom usage" do
      pattern = WeakRandom.pattern()
      
      vulnerable_code = [
        "int value = ThreadLocalRandom.current().nextInt();",
        "ThreadLocalRandom.current().nextDouble()",
        "long random = ThreadLocalRandom.current().nextLong();",
        "boolean flag = ThreadLocalRandom.current().nextBoolean();",
        "float randomFloat = ThreadLocalRandom.current().nextFloat();",
        "ThreadLocalRandom.current().nextBytes(buffer);",
        "int range = ThreadLocalRandom.current().nextInt(1, 100);"
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "does not match secure random implementations" do
      pattern = WeakRandom.pattern()
      
      safe_code = [
        "SecureRandom secureRandom = new SecureRandom();",
        "SecureRandom random = SecureRandom.getInstanceStrong();",
        "// Random rand = new Random();",
        "String comment = \"Use Math.random() carefully\";",
        "import java.util.Random;",
        "class Random { }",
        "private static final String RANDOM = \"random\";",
        "public void randomMethod() { }"
      ]
      
      for code <- safe_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        refute Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should not match: #{code}"
      end
    end
    
    test "detects Random with various constructor patterns" do
      pattern = WeakRandom.pattern()
      
      vulnerable_code = [
        "new Random()",
        "new Random(42)",
        "new Random(System.nanoTime())",
        "new Random(seedValue)",
        "new Random(Long.valueOf(seed))",
        "Random r = new Random((int) System.currentTimeMillis());",
        "this.random = new Random(customSeed);"
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects Random usage in cryptographic contexts" do
      pattern = WeakRandom.pattern()
      
      vulnerable_code = [
        "byte[] key = generateKey(random);",
        "String password = generatePassword(new Random());",
        "int nonce = random.nextInt();",
        "String challenge = createChallenge(Math.random());",
        "UUID uuid = new UUID(random.nextLong(), random.nextLong());",
        "String hash = generateHash(random.nextBytes(16));",
        "long timestamp = System.currentTimeMillis() + random.nextInt();"
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
      metadata = WeakRandom.vulnerability_metadata()
      
      assert String.contains?(String.downcase(metadata.description), "random") and
             String.contains?(String.downcase(metadata.description), "predictable")
      assert String.contains?(String.downcase(metadata.description), "cryptographic")
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 4
      assert length(metadata.real_world_impact) >= 4
      assert length(metadata.cve_examples) >= 2
    end
    
    test "includes random-specific information" do
      metadata = WeakRandom.vulnerability_metadata()
      
      assert String.contains?(metadata.description, "random") or String.contains?(metadata.description, "PRNG")
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "SecureRandom")) or
             Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "cryptographically"))
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "secure")) or
             Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "unpredictable"))
    end
    
    test "includes proper security references" do
      metadata = WeakRandom.vulnerability_metadata()
      
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
    
    test "includes OWASP Top 10 information" do
      metadata = WeakRandom.vulnerability_metadata()
      
      assert Enum.any?(metadata.references, fn ref ->
        String.contains?(String.downcase(ref.title), "owasp") and 
        String.contains?(String.downcase(ref.title), "a02")
      end)
    end
    
    test "includes CVE examples with proper structure" do
      metadata = WeakRandom.vulnerability_metadata()
      
      for cve <- metadata.cve_examples do
        assert Map.has_key?(cve, :id)
        assert Map.has_key?(cve, :description)
        assert Map.has_key?(cve, :severity)
        assert Map.has_key?(cve, :cvss)
        assert is_number(cve.cvss)
        assert cve.cvss > 0
      end
    end
    
    test "includes random-specific attack information" do
      metadata = WeakRandom.vulnerability_metadata()
      
      assert Enum.any?(metadata.additional_context.secure_patterns, fn pattern ->
        String.contains?(String.downcase(pattern), "securerandom") or
        String.contains?(String.downcase(pattern), "cryptographically") or
        String.contains?(String.downcase(pattern), "unpredictable")
      end)
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = WeakRandom.ast_enhancement()
      
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.7
    end
    
    test "includes random number generation analysis" do
      enhancement = WeakRandom.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "MethodInvocation" or
             enhancement.ast_rules.node_type == "ObjectCreationExpression"
      assert enhancement.ast_rules.random_analysis.check_random_usage
      assert enhancement.ast_rules.random_analysis.random_classes
      assert enhancement.ast_rules.random_analysis.check_constructor_calls
    end
    
    test "has security context detection rules" do
      enhancement = WeakRandom.ast_enhancement()
      
      assert enhancement.ast_rules.security_analysis.check_security_context
      assert enhancement.ast_rules.security_analysis.security_indicators
      assert enhancement.ast_rules.security_analysis.crypto_contexts
    end
    
    test "includes method call analysis" do
      enhancement = WeakRandom.ast_enhancement()
      
      assert enhancement.ast_rules.method_analysis.check_random_methods
      assert enhancement.ast_rules.method_analysis.random_method_names
      assert enhancement.ast_rules.method_analysis.dangerous_method_patterns
    end
    
    test "includes token generation analysis" do
      enhancement = WeakRandom.ast_enhancement()
      
      assert enhancement.ast_rules.token_analysis.check_token_generation
      assert enhancement.ast_rules.token_analysis.token_patterns
      assert enhancement.ast_rules.token_analysis.password_patterns
    end
    
    test "includes context-based filtering" do
      enhancement = WeakRandom.ast_enhancement()
      
      assert enhancement.context_rules.check_security_usage
      assert enhancement.context_rules.secure_random_sources
      assert enhancement.context_rules.weak_random_indicators
    end
    
    test "has proper confidence scoring" do
      enhancement = WeakRandom.ast_enhancement()
      
      adjustments = enhancement.confidence_rules.adjustments
      assert Map.has_key?(adjustments, "uses_secure_random")
      assert Map.has_key?(adjustments, "in_security_context")
      assert Map.has_key?(adjustments, "in_test_code")
      assert Map.has_key?(adjustments, "for_games_simulation")
    end
  end
end