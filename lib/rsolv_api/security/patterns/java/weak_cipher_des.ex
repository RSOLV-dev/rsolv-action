defmodule RsolvApi.Security.Patterns.Java.WeakCipherDes do
  @moduledoc """
  Weak Cryptography - DES pattern for Java code.
  
  Detects usage of DES (Data Encryption Standard) and 3DES (Triple DES) cipher algorithms
  which are cryptographically weak and deprecated. DES uses a 56-bit key size making it
  vulnerable to brute-force attacks, while 3DES is vulnerable to Sweet32 birthday attacks
  due to its 64-bit block size.
  
  ## Vulnerability Details
  
  DES (Data Encryption Standard) is a symmetric-key block cipher that was once widely used
  but is now considered insecure due to its small key size (56 bits). Modern computing power
  can break DES encryption in hours or days using brute force attacks. Triple DES (3DES)
  was developed as a stopgap measure but is also deprecated due to Sweet32 birthday attacks.
  
  ### Attack Examples
  
  ```java
  // Vulnerable code - DES cipher
  Cipher cipher = Cipher.getInstance("DES");
  cipher.init(Cipher.ENCRYPT_MODE, secretKey);
  
  // Vulnerable code - Triple DES
  Cipher tripleDes = Cipher.getInstance("DESede/ECB/PKCS5Padding");
  
  // Attack vectors:
  // 1. Brute force attack on 56-bit DES key space (2^56 = ~72 quadrillion keys)
  // 2. Sweet32 birthday attack on 3DES 64-bit blocks after ~32GB of data
  ```
  
  ## References
  
  - CWE-327: Use of a Broken or Risky Cryptographic Algorithm
  - OWASP A02:2021 - Cryptographic Failures
  - CVE-2016-2183: Sweet32 birthday attack on 3DES
  - NIST deprecation of 3DES effective 2024
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "java-weak-cipher-des",
      name: "Weak Cryptography - DES",
      description: "DES and 3DES encryption algorithms are cryptographically weak and deprecated",
      type: :weak_crypto,
      severity: :high,
      languages: ["java"],
      regex: [
        # Cipher.getInstance with DES variants - exclude comments
        ~r/^(?!.*\/\/).*Cipher\.getInstance\s*\(\s*[\"'](?:DES|DESede|TripleDES|3DES)/im,
        # String literals containing DES algorithm names - exclude comments
        ~r/^(?!.*\/\/).*[\"'](?:DES|DESede|TripleDES|3DES)(?:\/[^\"']*)?[\"']/m,
        # Variable assignments with DES algorithms - exclude comments
        ~r/^(?!.*\/\/).*(?:algorithm|cipher|transformation)\s*=\s*[\"'](?:DES|DESede|TripleDES|3DES)/im,
        # KeyGenerator and SecretKeySpec with DES - exclude comments
        ~r/^(?!.*\/\/).*(?:KeyGenerator|SecretKeySpec|SecretKeyFactory).*[\"'](?:DES|DESede|TripleDES|3DES)[\"']/im,
        # Method calls with DES algorithms - exclude comments
        ~r/^(?!.*\/\/).*\.(?:getInstance|init)\s*\([^)]*[\"'](?:DES|DESede|TripleDES|3DES)/im
      ],
      default_tier: :ai,
      cwe_id: "CWE-327",
      owasp_category: "A02:2021",
      recommendation: "Use AES with 256-bit keys (AES/GCM/NoPadding) or other modern encryption algorithms instead of DES/3DES",
      test_cases: %{
        vulnerable: [
          ~S|Cipher cipher = Cipher.getInstance("DES");|,
          ~S|Cipher.getInstance("DESede/ECB/PKCS5Padding");|,
          ~S|new SecretKeySpec(keyBytes, "DES");|,
          ~S|KeyGenerator.getInstance("TripleDES");|
        ],
        safe: [
          ~S|Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");|,
          ~S|Cipher.getInstance("AES/CBC/PKCS5Padding");|,
          ~S|new SecretKeySpec(keyBytes, "AES");|,
          ~S|// DES is deprecated, use AES instead|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      DES (Data Encryption Standard) is a symmetric-key block cipher that uses a 56-bit key size,
      making it vulnerable to brute-force attacks. Modern computing power, including specialized
      hardware and distributed computing, can break DES encryption in a matter of hours or days.
      
      Triple DES (3DES/DESede) was developed as an interim solution by applying DES three times
      with different keys, but it is also deprecated due to several weaknesses:
      - Sweet32 birthday attack exploiting 64-bit block size
      - Performance issues compared to modern algorithms
      - NIST official deprecation as of 2024
      
      Key vulnerabilities:
      - DES: 56-bit key space allows brute force attacks (2^56 ≈ 72 quadrillion keys)
      - 3DES: Sweet32 birthday attack after processing ~32GB of data with same key
      - Both use 64-bit block size making them vulnerable to block collision attacks
      - Performance penalties compared to AES
      - No longer meet modern security standards
      
      Common vulnerable usage patterns:
      - Legacy system encryption without key rotation
      - Payment card industry systems (deprecated in PCI DSS)
      - File encryption and data at rest protection
      - Network protocol encryption (TLS, VPN)
      - Database encryption for sensitive data
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-327",
          title: "Use of a Broken or Risky Cryptographic Algorithm",
          url: "https://cwe.mitre.org/data/definitions/327.html"
        },
        %{
          type: :owasp,
          id: "A02:2021",
          title: "OWASP Top 10 2021 - A02 Cryptographic Failures",
          url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
        },
        %{
          type: :research,
          id: "sweet32_attack",
          title: "Sweet32: Birthday attacks on 64-bit block ciphers in TLS and OpenVPN",
          url: "https://sweet32.info/"
        },
        %{
          type: :research,
          id: "nist_3des_deprecation",
          title: "NIST to Withdraw Special Publication 800-67 Revision 2 (3DES)",
          url: "https://csrc.nist.gov/news/2023/nist-to-withdraw-sp-800-67-rev-2"
        },
        %{
          type: :research,
          id: "des_security_analysis",
          title: "DES and Triple DES are now insecure - Datadog Security",
          url: "https://docs.datadoghq.com/security/code_security/static_analysis/static_analysis_rules/go-security/import-des/"
        }
      ],
      attack_vectors: [
        "Brute force attack: Exhaustive key search through 2^56 DES key space",
        "Sweet32 birthday attack: Collision attack on 3DES after ~32GB of data",
        "Known-plaintext attack: Exploiting patterns in encrypted data",
        "Chosen-plaintext attack: Manipulating input to reveal key information",
        "Meet-in-the-middle attack: Reducing effective key strength of 3DES",
        "Block collision attack: Exploiting 64-bit block size patterns"
      ],
      real_world_impact: [
        "Payment card data breach through weak PCI DSS encryption",
        "Government and military communications compromise",
        "Banking and financial transaction interception",
        "Healthcare records exposure violating HIPAA requirements",
        "Corporate data theft through legacy system exploitation",
        "Compliance violations resulting in regulatory fines",
        "Reputation damage from security incident disclosure"
      ],
      cve_examples: [
        %{
          id: "CVE-2016-2183",
          description: "Sweet32 birthday attack against 3DES in TLS, SSH, and IPSec protocols",
          severity: "medium",
          cvss: 5.9,
          note: "Birthday attack allows recovery of plaintext from long-duration encrypted sessions"
        },
        %{
          id: "CVE-2016-6329", 
          description: "Sweet32 birthday attack vulnerability in OpenVPN using 3DES",
          severity: "medium",
          cvss: 5.9,
          note: "64-bit block ciphers vulnerable to collision attacks in CBC mode"
        }
      ],
      detection_notes: """
      This pattern detects DES/3DES usage in various contexts:
      - Cipher.getInstance() calls with DES, DESede, TripleDES, or 3DES
      - String literals containing DES algorithm identifiers
      - Variable assignments specifying DES as encryption algorithm  
      - KeyGenerator, SecretKeySpec, and SecretKeyFactory with DES algorithms
      - Method calls passing DES algorithms as parameters
      - Cipher transformation strings including DES with modes/padding
      
      The pattern covers both basic DES and Triple DES variants, including
      their common naming conventions and usage patterns in Java cryptography.
      """,
      safe_alternatives: [
        "Use AES-256: Cipher.getInstance(\"AES/GCM/NoPadding\") for authenticated encryption",
        "Use AES-CBC: Cipher.getInstance(\"AES/CBC/PKCS5Padding\") with proper IV",
        "For streaming: Use ChaCha20-Poly1305 for high-performance encryption",
        "For legacy compatibility: Use AES-128 as minimum acceptable security",
        "For key exchange: Use ECDH or RSA-2048+ for key establishment",
        "For passwords: Use Argon2, bcrypt, or PBKDF2 for key derivation",
        "For digital signatures: Use RSA-2048+ or ECDSA with SHA-256+"
      ],
      additional_context: %{
        common_mistakes: [
          "Using DES/3DES because it's 'good enough' for internal systems",
          "Believing 3DES is secure because it uses three encryption rounds",
          "Implementing DES for performance reasons (AES is actually faster)",
          "Using DES in new applications due to legacy code examples",
          "Thinking short-lived sessions are immune to Sweet32 attacks",
          "Mixing strong and weak ciphers in the same application"
        ],
        secure_patterns: [
          "Always use AES with 128-bit minimum, 256-bit preferred key sizes",
          "Use authenticated encryption modes like GCM or Poly1305",
          "Implement proper key rotation and management practices",
          "Use cipher suites that exclude all DES variants",
          "Regularly audit cryptographic algorithm usage",
          "Follow current NIST and industry security guidelines"
        ],
        sweet32_attack_details: [
          "Affects all 64-bit block ciphers including DES and 3DES",
          "Requires ~2^32 blocks (~32GB) of data encrypted with same key",
          "Exploits birthday paradox to find block collisions",
          "Allows recovery of plaintext from observed ciphertext patterns",
          "Mitigated by using 128-bit block ciphers like AES"
        ],
        compliance_considerations: [
          "PCI DSS prohibits DES and requires 3DES migration by 2024",
          "FIPS 140-2 deprecates DES and restricts 3DES usage",
          "NIST SP 800-131A disallows DES and limits 3DES to legacy systems",
          "SOX compliance may require migration from weak encryption",
          "GDPR Article 32 requires 'state of the art' encryption (excludes DES)",
          "HIPAA security rule requires appropriate encryption (DES insufficient)"
        ],
        performance_comparison: [
          "AES-128 is typically 3-5x faster than 3DES on modern hardware",
          "AES has hardware acceleration on most modern processors",
          "3DES requires 3x the computation of single DES",
          "AES-GCM provides both encryption and authentication efficiently",
          "ChaCha20 offers excellent performance on mobile devices"
        ]
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual cryptographic usage of DES
  and acceptable references in comments, documentation, or legacy compatibility code.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Java.WeakCipherDes.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Java.WeakCipherDes.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
      
      iex> enhancement = RsolvApi.Security.Patterns.Java.WeakCipherDes.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "MethodInvocation"
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "MethodInvocation",
        cipher_analysis: %{
          check_method_name: true,
          cipher_methods: ["getInstance", "init", "doFinal", "update"],
          check_algorithm_parameter: true,
          weak_algorithms: ["DES", "DESede", "TripleDES", "3DES"],
          check_transformation_string: true
        },
        algorithm_detection: %{
          check_string_literals: true,
          weak_algorithm_patterns: ["DES", "DESede", "TripleDES", "3DES"],
          check_variable_assignments: true,
          check_method_parameters: true,
          algorithm_variable_names: ["algorithm", "cipher", "transformation", "cipherType", "encryptionMethod"]
        },
        key_analysis: %{
          check_key_generation: true,
          key_generator_methods: ["getInstance", "generateKey"],
          weak_key_algorithms: ["DES", "DESede", "TripleDES", "3DES"],
          check_secret_key_spec: true,
          key_factory_methods: ["getInstance", "generateSecret"]
        }
      },
      context_rules: %{
        check_cryptographic_context: true,
        high_risk_contexts: [
          "data encryption",
          "file encryption", 
          "network encryption",
          "payment processing",
          "authentication systems",
          "session management",
          "TLS/SSL implementations",
          "VPN connections"
        ],
        deprecated_algorithms: ["DES", "DESede", "TripleDES", "3DES"],
        strong_algorithms: ["AES", "ChaCha20", "AES-GCM", "AES-CTR", "AES-CBC"],
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/example/, ~r/demo/],
        check_variable_context: true,
        sweet32_indicators: ["64-bit", "birthday", "collision", "block cipher"]
      },
      confidence_rules: %{
        base: 0.9,
        adjustments: %{
          "is_cryptographic_context" => 0.1,
          "has_security_variable_name" => 0.05,
          "in_encryption_code" => 0.1,
          "uses_weak_mode" => 0.1,
          "in_legacy_compatibility" => -0.2,
          "in_test_code" => -0.5,
          "is_commented_out" => -0.8,
          "has_migration_comment" => -0.1,
          "is_documentation" => -0.6
        }
      },
      min_confidence: 0.8
    }
  end
end