defmodule RsolvApi.Security.Patterns.Java.WeakRandom do
  @moduledoc """
  Weak Random Number Generation pattern for Java code.
  
  Detects usage of cryptographically weak pseudo-random number generators (PRNGs) in Java
  applications where cryptographically secure randomness is required. Using weak PRNGs like
  java.util.Random or Math.random() in security-sensitive contexts can lead to predictable
  values that attackers can exploit.
  
  ## Vulnerability Details
  
  Weak PRNG vulnerabilities occur when applications use standard pseudo-random number
  generators for security purposes. These generators are designed for statistical randomness
  but not cryptographic security, making their output predictable and exploitable.
  
  Common vulnerable patterns:
  - Using java.util.Random for token, password, or key generation
  - Using Math.random() for security-sensitive random values
  - Using ThreadLocalRandom for cryptographic purposes
  - Generating session IDs, CSRF tokens, or API keys with weak PRNGs
  - Creating salts, nonces, or initialization vectors with predictable randomness
  
  ### Attack Examples
  
  ```java
  // Vulnerable code - weak PRNG for token generation
  Random random = new Random();
  String token = String.valueOf(random.nextLong());
  
  // Vulnerable code - Math.random() for session ID
  String sessionId = String.valueOf((int)(Math.random() * 1000000));
  
  // Vulnerable code - ThreadLocalRandom for cryptographic key
  byte[] key = new byte[16];
  ThreadLocalRandom.current().nextBytes(key);
  ```
  
  ## References
  
  - CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator
  - OWASP A02:2021 - Cryptographic Failures
  - CVE-2024-29868: Apache StreamPipes weak PRNG in password recovery
  - CVE-2013-6386: Drupal weak PRNG allowing account takeover
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @doc """
  Pattern detects weak random number generation in Java code.
  
  Identifies usage of cryptographically weak PRNGs in contexts where secure
  randomness is required, leading to predictable values that can be exploited.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Java.WeakRandom.pattern()
      iex> pattern.id
      "java-weak-random"
      
      iex> pattern = RsolvApi.Security.Patterns.Java.WeakRandom.pattern()
      iex> pattern.severity
      :medium
      
      iex> pattern = RsolvApi.Security.Patterns.Java.WeakRandom.pattern()
      iex> vulnerable = "Random rand = new Random();"
      iex> Enum.any?(pattern.regex, fn r -> Regex.match?(r, vulnerable) end)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Java.WeakRandom.pattern()
      iex> safe = "SecureRandom secureRandom = new SecureRandom();"
      iex> Enum.any?(pattern.regex, fn r -> Regex.match?(r, safe) end)
      false
  """
  @impl true
  def pattern do
    %Pattern{
      id: "java-weak-random",
      name: "Weak Random Number Generation",
      description: "Usage of cryptographically weak pseudo-random number generators",
      type: :insecure_random,
      severity: :medium,
      languages: ["java"],
      regex: [
        # java.util.Random instantiation - exclude commented lines and strings
        ~r/^(?!.*\/\/)(?!.*["']).*new\s+Random\s*\(/im,
        # Math.random() method calls - exclude commented lines and strings
        ~r/^(?!.*\/\/)(?!.*["']).*Math\.random\s*\(\)/im,
        # ThreadLocalRandom usage - exclude commented lines
        ~r/^(?!.*\/\/).*ThreadLocalRandom\.current\(\)/im,
        # Random method calls on instances - exclude commented lines
        ~r/^(?!.*\/\/).*\.next(?:Int|Long|Double|Float|Boolean|Bytes)\s*\(/im,
        # Random field/variable usage in method calls - exclude commented lines
        ~r/^(?!.*\/\/).*(?:random|rand|rng|generator)\.next/im,
        # Method calls with random parameters - exclude commented lines
        ~r/^(?!.*\/\/).*\w+\s*\(\s*(?:[^)]*,\s*)?(?:random|rand|rng|generator)(?:\s*,\s*[^)]*)?\s*\)/im
      ],
      cwe_id: "CWE-338",
      owasp_category: "A02:2021",
      recommendation: "Use SecureRandom for cryptographically secure random number generation",
      test_cases: %{
        vulnerable: [
          ~S|Random rand = new Random();|,
          ~S|double randomValue = Math.random();|,
          ~S|int value = ThreadLocalRandom.current().nextInt();|,
          ~S|int token = random.nextInt(1000000);|,
          ~S|byte[] bytes = new byte[16]; random.nextBytes(bytes);|
        ],
        safe: [
          ~S|SecureRandom secureRandom = new SecureRandom();|,
          ~S|SecureRandom random = SecureRandom.getInstanceStrong();|,
          ~S|// Random rand = new Random();|,
          ~S|import java.util.Random;|,
          ~S|class Random { }|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Weak pseudo-random number generator (PRNG) vulnerabilities occur when applications use
      standard random number generators like java.util.Random, Math.random(), or ThreadLocalRandom
      for security-sensitive operations. These generators are designed for statistical randomness
      but not cryptographic security, making their output predictable and exploitable by attackers.
      
      Weak PRNG usage can lead to:
      - Predictable session IDs and authentication tokens
      - Guessable passwords and password reset tokens
      - Exploitable cryptographic keys and initialization vectors
      - Predictable CSRF tokens and API keys
      - Compromised salts and nonces in cryptographic operations
      
      The vulnerability is particularly dangerous because:
      - Standard PRNGs use deterministic algorithms with known mathematical properties
      - Seed values are often predictable (system time, process ID, etc.)
      - Attackers can predict future values if they observe some outputs
      - Large-scale attacks become feasible with predictable randomness
      - Many developers are unaware of the security implications
      
      Historical context:
      - Weak PRNG attacks have been documented since the early days of computing
      - Featured in OWASP Top 10 2021 under A02 (Cryptographic Failures)
      - Critical vulnerabilities in major frameworks and applications
      - Common attack vector in penetration testing and security research
      - Regulatory compliance issues with standards requiring cryptographic security
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-338",
          title: "Use of Cryptographically Weak Pseudo-Random Number Generator",
          url: "https://cwe.mitre.org/data/definitions/338.html"
        },
        %{
          type: :owasp,
          id: "A02:2021",
          title: "OWASP Top 10 2021 - A02 Cryptographic Failures", 
          url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
        },
        %{
          type: :research,
          id: "owasp_insecure_randomness",
          title: "OWASP Insecure Randomness",
          url: "https://owasp.org/www-community/vulnerabilities/Insecure_Randomness"
        },
        %{
          type: :research,
          id: "owasp_weak_encryption_testing",
          title: "OWASP Testing for Weak Encryption",
          url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/04-Testing_for_Weak_Encryption"
        },
        %{
          type: :research,
          id: "elttam_cracking_randomness",
          title: "Cracking the Odd Case of Randomness in Java",
          url: "https://www.elttam.com/blog/cracking-randomness-in-java/"
        }
      ],
      attack_vectors: [
        "Seed prediction: Attackers analyze seed generation patterns to predict PRNG state",
        "Output analysis: Observing random outputs to deduce internal PRNG state and predict future values",
        "Time-based attacks: Using predictable seed values like system timestamps to reproduce PRNG sequences",
        "Brute force seed recovery: Exhaustively testing possible seed values for small seed spaces",
        "Statistical analysis: Exploiting mathematical weaknesses in PRNG algorithms for prediction",
        "Account takeover: Using predictable password reset tokens to compromise user accounts",
        "Session hijacking: Predicting session IDs to impersonate legitimate users"
      ],
      real_world_impact: [
        "Apache StreamPipes CVE-2024-29868: Weak PRNG in password recovery allowing account takeover",
        "Drupal CVE-2013-6386: mt_rand() predictable seeds enabling remote account compromise",
        "Android Bitcoin wallet vulnerabilities: Weak PRNG leading to private key prediction and theft",
        "E-commerce platform breaches: Predictable session IDs enabling unauthorized access",
        "IoT device compromises: Weak random number generation in device authentication",
        "Gaming platform exploits: Predictable random values in loot boxes and rewards",
        "Financial services attacks: Weak PRNG in trading platforms enabling market manipulation"
      ],
      cve_examples: [
        %{
          id: "CVE-2024-29868",
          description: "Apache StreamPipes weak PRNG in user self-registration and password recovery mechanism",
          severity: "high",
          cvss: 7.5,
          note: "Allows attackers to guess recovery tokens and take over user accounts"
        },
        %{
          id: "CVE-2013-6386",
          description: "Drupal uses PHP mt_rand() with predictable seeds for user account password reset tokens",
          severity: "critical",
          cvss: 9.0,
          note: "Remote attackers can determine administrator passwords and gain unauthorized access"
        },
        %{
          id: "CVE-2006-3419",
          description: "Multiple applications use weak PRNG for session management enabling session hijacking",
          severity: "medium",
          cvss: 6.4,
          note: "Predictable session identifiers allow attackers to impersonate legitimate users"
        }
      ],
      detection_notes: """
      This pattern detects insecure random number generation by identifying:
      
      1. java.util.Random instantiation using 'new Random()' constructor calls
      2. Math.random() method invocations for generating random values
      3. ThreadLocalRandom.current() usage which is not cryptographically secure
      4. Random instance method calls (.nextInt(), .nextLong(), .nextBytes(), etc.)
      5. Named random variables being used in method calls (random.next*, rand.next*, etc.)
      
      The pattern uses negative lookahead to exclude commented lines and focuses on:
      - Constructor calls creating new Random instances
      - Static method calls to Math.random() and ThreadLocalRandom
      - Instance method calls on random number generators
      - Common variable naming patterns for random generators
      
      Key detection criteria:
      - Looks for instantiation and usage patterns of weak PRNGs
      - Excludes commented code and import statements
      - Covers both direct usage and method chaining scenarios
      - Identifies common random variable naming conventions
      """,
      safe_alternatives: [
        "Use java.security.SecureRandom for all cryptographic random number generation",
        "Use SecureRandom.getInstanceStrong() for highest security applications",
        "Generate proper entropy using SecureRandom.generateSeed() for seeding",
        "Use cryptographically secure libraries like Bouncy Castle for specialized needs",
        "Implement proper random number validation and testing procedures",
        "Use hardware security modules (HSMs) for critical cryptographic operations",
        "Apply NIST SP 800-90A recommendations for random number generation",
        "Regular security audits of random number usage in security contexts"
      ],
      additional_context: %{
        common_mistakes: [
          "Assuming java.util.Random is secure because it's in the standard library",
          "Using System.currentTimeMillis() as a seed thinking it provides security",
          "Believing that ThreadLocalRandom is more secure than java.util.Random",
          "Using weak PRNGs for 'just testing' that accidentally reach production",
          "Thinking that seeding with multiple values makes weak PRNGs secure",
          "Using Math.random() because it's convenient and appears random",
          "Not understanding the difference between statistical and cryptographic randomness"
        ],
        secure_patterns: [
          "Always use SecureRandom for security-sensitive random generation",
          "Initialize SecureRandom without explicit seeding to use system entropy",
          "Use SecureRandom.getInstanceStrong() for maximum security requirements",
          "Implement proper random number testing using NIST statistical test suites",
          "Use dedicated cryptographic libraries for specialized random number needs",
          "Regular security reviews of all random number usage in the application",
          "Document and validate all sources of randomness in security architecture",
          "Implement fallback mechanisms for entropy pool depletion scenarios"
        ],
        prng_types: [
          "java.util.Random: Linear congruential generator, predictable with known seed",
          "Math.random(): Typically uses same underlying algorithm as java.util.Random",
          "ThreadLocalRandom: Enhanced performance but still not cryptographically secure",
          "SecureRandom: Cryptographically strong using OS entropy sources",
          "Hardware RNGs: Dedicated hardware for true random number generation"
        ],
        java_specific_considerations: [
          "java.util.Random uses a 48-bit seed with predictable linear congruential formula",
          "Math.random() implementation varies by JVM but typically not cryptographically secure",
          "ThreadLocalRandom provides better performance but same security issues as Random",
          "SecureRandom automatically seeds from OS entropy sources (/dev/random, /dev/urandom)",
          "Different platforms provide different SecureRandom implementations",
          "SecureRandom blocking behavior varies between operating systems"
        ],
        compliance_impact: [
          "FIPS 140-2: Requires cryptographically secure random number generation for compliance",
          "PCI DSS: Credit card processing must use approved random number generators",
          "HIPAA: Healthcare applications require secure randomness for patient data protection",
          "SOX: Financial systems must use secure random generation for audit trails",
          "GDPR: Personal data protection requires cryptographically secure random values",
          "ISO 27001: Information security standards mandate proper random number generation"
        ]
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between security-sensitive random number usage
  and acceptable uses of weak PRNGs for non-cryptographic purposes.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Java.WeakRandom.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Java.WeakRandom.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
      
      iex> enhancement = RsolvApi.Security.Patterns.Java.WeakRandom.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "MethodInvocation"
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "MethodInvocation",
        random_analysis: %{
          check_random_usage: true,
          random_classes: ["Random", "ThreadLocalRandom"],
          random_methods: ["nextInt", "nextLong", "nextDouble", "nextFloat", "nextBoolean", "nextBytes"],
          check_constructor_calls: true,
          check_static_methods: true,
          static_random_methods: ["Math.random", "ThreadLocalRandom.current"]
        },
        security_analysis: %{
          check_security_context: true,
          security_indicators: [
            "token", "password", "key", "secret", "session", "csrf", "auth", "nonce", 
            "salt", "iv", "seed", "challenge", "otp", "uuid", "guid"
          ],
          crypto_contexts: [
            "authentication", "authorization", "encryption", "signing", "verification",
            "password_reset", "session_management", "api_key_generation"
          ],
          security_method_patterns: ["generate", "create", "init", "reset", "verify"]
        },
        method_analysis: %{
          check_random_methods: true,
          random_method_names: ["nextInt", "nextLong", "nextDouble", "nextFloat", "nextBoolean", "nextBytes"],
          dangerous_method_patterns: ["random", "rand", "rng", "generator"],
          check_method_chaining: true,
          security_return_types: ["String", "byte[]", "int", "long", "UUID"]
        },
        token_analysis: %{
          check_token_generation: true,
          token_patterns: ["token", "id", "key", "password", "secret", "hash"],
          password_patterns: ["password", "passwd", "pwd", "passphrase"],
          session_patterns: ["session", "sessionId", "sessionToken", "cookie"],
          api_patterns: ["apiKey", "accessToken", "authToken", "bearerToken"]
        }
      },
      context_rules: %{
        check_security_usage: true,
        secure_random_sources: [
          "SecureRandom",
          "SecureRandom.getInstanceStrong",
          "SecureRandom.getInstance", 
          "CryptoRandom",
          "SystemRandom",
          "OSRandom"
        ],
        weak_random_indicators: [
          "random_in_security_context",
          "token_generation_with_weak_prng",
          "password_generation_with_random",
          "session_id_with_weak_randomness"
        ],
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/example/, ~r/demo/, ~r/sample/],
        acceptable_contexts: [
          "games", "simulation", "testing", "benchmarking", "mathematical_operations",
          "ui_effects", "non_security_randomization", "performance_testing"
        ],
        high_risk_contexts: [
          "authentication", "session_management", "password_generation", "key_generation",
          "token_creation", "cryptographic_operations", "security_challenges"
        ]
      },
      confidence_rules: %{
        base: 0.6,
        adjustments: %{
          "uses_secure_random" => -0.8,
          "in_security_context" => 0.3,
          "generates_tokens" => 0.2,
          "in_crypto_context" => 0.2,
          "in_authentication_context" => 0.2,
          "in_test_code" => -0.4,
          "for_games_simulation" => -0.3,
          "for_ui_effects" => -0.3,
          "is_commented_out" => -0.9,
          "mathematical_operations" => -0.2,
          "performance_testing" => -0.3
        }
      },
      min_confidence: 0.7
    }
  end
end