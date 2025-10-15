defmodule Rsolv.Security.Patterns.Java.WeakHashMd5 do
  @moduledoc """
  Weak Cryptography - MD5 pattern for Java code.

  Detects usage of MD5 hash algorithm which is cryptographically broken and vulnerable
  to collision attacks. MD5 should not be used for any security-sensitive purposes
  including password hashing, digital signatures, or data integrity verification.

  ## Vulnerability Details

  MD5 (Message Digest 5) is a cryptographic hash function that produces a 128-bit hash value.
  However, it is fundamentally broken due to its vulnerability to collision attacks, where
  attackers can create two different inputs that produce the same hash output. This breaks
  the fundamental property of cryptographic hash functions.

  ### Attack Example

  ```java
  // Vulnerable code
  MessageDigest md = MessageDigest.getInstance("MD5");
  String passwordHash = bytesToHex(md.digest(password.getBytes()));

  // Attack: MD5 collision allows creation of different passwords with same hash
  // Attacker can forge digital signatures or bypass authentication
  ```

  ## References

  - CWE-327: Use of a Broken or Risky Cryptographic Algorithm
  - OWASP A02:2021 - Cryptographic Failures
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @impl true
  def pattern do
    %Pattern{
      id: "java-weak-hash-md5",
      name: "Weak Cryptography - MD5",
      description:
        "MD5 algorithm is cryptographically broken and vulnerable to collision attacks",
      type: :weak_crypto,
      severity: :medium,
      languages: ["java"],
      regex: [
        # MessageDigest.getInstance with MD5 - exclude comments
        ~r/^(?!.*\/\/).*MessageDigest\.getInstance\s*\(\s*[\"']MD5[\"']\s*\)/m,
        # String literals containing MD5 as algorithm - exclude comments
        ~r/^(?!.*\/\/).*[\"']MD5[\"']/m,
        # Method names containing MD5
        ~r/(?:compute|calculate|generate|get)MD5(?:Hash|Digest)?/i,
        # Variable assignments with MD5 - exclude comments
        ~r/^(?!.*\/\/).*(?:algorithm|digest|hash|hashType)\s*=\s*[\"']MD5[\"']/im,
        # MD5 in method calls - exclude comments
        ~r/^(?!.*\/\/).*\.(?:createHash|getDigest|hash)\s*\(\s*[\"']MD5[\"']/im,
        # Enum or constant references to MD5
        ~r/HashAlgorithm\.MD5|ALGORITHM_MD5|MD5_ALGORITHM/
      ],
      cwe_id: "CWE-327",
      owasp_category: "A02:2021",
      recommendation: "Use SHA-256, SHA-3, or other secure hash algorithms instead of MD5",
      test_cases: %{
        vulnerable: [
          ~S|MessageDigest md = MessageDigest.getInstance("MD5");|,
          ~S|MessageDigest.getInstance("MD5").digest(password.getBytes());|
        ],
        safe: [
          ~S|MessageDigest md = MessageDigest.getInstance("SHA-256");|,
          ~S|BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
String hashedPassword = encoder.encode(password);|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      MD5 (Message Digest Algorithm 5) is a cryptographic hash function that produces
      a 128-bit hash value. However, MD5 is fundamentally broken and should never be
      used for security-sensitive purposes. The algorithm is vulnerable to collision
      attacks where attackers can create two different inputs that produce identical
      hash outputs.

      Key vulnerabilities of MD5:
      - Collision attacks can be performed in seconds on modern hardware
      - Pre-image attacks are theoretically possible with sufficient computing power
      - Length extension attacks are possible in certain contexts
      - Not suitable for password hashing due to speed and collision vulnerabilities

      Common vulnerable usage patterns:
      - Password hashing and storage
      - Digital signature generation
      - Data integrity verification
      - Session token generation
      - API key or token derivation
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
          id: "md5_collisions_cert",
          title: "MD5 vulnerable to collision attacks - US-CERT",
          url: "https://www.kb.cert.org/vuls/id/836068"
        },
        %{
          type: :research,
          id: "md5_insecure_guardrails",
          title: "Insecure Use of Cryptography - GuardRails",
          url: "https://docs.guardrails.io/docs/vulnerabilities/java/insecure_use_of_crypto"
        },
        %{
          type: :research,
          id: "cryptographic_failures_medium",
          title: "Cryptographic Failures: Understanding and Preventing Vulnerabilities",
          url:
            "https://medium.com/@ajay.monga73/cryptographic-failures-understanding-and-preventing-vulnerabilities-91c8b2c56854"
        }
      ],
      attack_vectors: [
        "Collision attack: Create two different files with the same MD5 hash",
        "Certificate forgery: Generate rogue SSL certificates with colliding hashes",
        "Digital signature bypass: Create alternate documents with same signature",
        "Password hash collision: Find alternate passwords that hash to same value",
        "Data integrity bypass: Modify files while maintaining the same checksum",
        "Session fixation: Generate predictable session tokens due to weak hashing"
      ],
      real_world_impact: [
        "Authentication bypass through password hash collisions",
        "Digital signature forgery enabling document tampering",
        "SSL/TLS certificate forgery for man-in-the-middle attacks",
        "Data integrity violations in file verification systems",
        "Session hijacking through predictable token generation",
        "Compliance violations (FIPS 140-2, Common Criteria prohibit MD5)",
        "Legal liability for using known-insecure cryptographic algorithms"
      ],
      cve_examples: [
        %{
          id: "CVE-2020-5229",
          description: "Opencast password storage using cryptographically insecure MD5",
          severity: "medium",
          cvss: 5.3,
          note: "Stored passwords using MD5 making them vulnerable to rainbow table attacks"
        },
        %{
          id: "CVE-2015-7575",
          description:
            "SLOTH - Weak MD5 signature hash vulnerability affecting multiple implementations",
          severity: "high",
          cvss: 7.1,
          note: "MD5 signature vulnerabilities in TLS connections enabling MitM attacks"
        }
      ],
      detection_notes: """
      This pattern detects MD5 usage in various contexts:
      - MessageDigest.getInstance("MD5") calls
      - String literals containing "MD5" as algorithm identifiers
      - Method names containing MD5 (computeMD5, generateMD5Hash, etc.)
      - Variable assignments where MD5 is specified as the algorithm
      - Method calls passing MD5 as hash algorithm parameter
      - Constants and enum references to MD5 algorithms

      The pattern looks for both direct MessageDigest usage and indirect references
      to MD5 through variables, constants, and method parameters.
      """,
      safe_alternatives: [
        "Use SHA-256: MessageDigest.getInstance(\"SHA-256\") for general hashing",
        "Use SHA-3: MessageDigest.getInstance(\"SHA3-256\") for modern applications",
        "For passwords: Use BCrypt, scrypt, or Argon2 (not plain hashing)",
        "For HMAC: Use HMAC-SHA256 instead of HMAC-MD5",
        "For digital signatures: Use SHA-256 or higher with RSA/ECDSA",
        "For checksums: Use SHA-256 or CRC32 (non-cryptographic but collision-resistant)",
        "For UUIDs: Use SecureRandom with proper entropy sources"
      ],
      additional_context: %{
        common_mistakes: [
          "Using MD5 for 'non-security' purposes (still vulnerable to intentional attacks)",
          "Believing MD5 is acceptable for internal systems (insider threats exist)",
          "Using MD5 for performance reasons (modern SHA algorithms are fast enough)",
          "Thinking collision resistance doesn't matter for their use case",
          "Using MD5 because legacy systems require it (upgrade the legacy systems)"
        ],
        secure_patterns: [
          "Always use SHA-256 or higher for any hashing needs",
          "Use proper password hashing libraries (BCrypt, Argon2)",
          "Implement crypto-agility to easily upgrade algorithms",
          "Use HMAC with secure hash functions for authentication",
          "Regularly review and update cryptographic implementations"
        ],
        performance_notes: [
          "SHA-256 is only ~25% slower than MD5 on modern hardware",
          "Hardware acceleration makes SHA-256 very fast on modern CPUs",
          "Security benefits far outweigh minor performance costs",
          "Consider SHA-3 for new applications requiring future-proofing"
        ],
        compliance_considerations: [
          "FIPS 140-2 prohibits MD5 for cryptographic purposes",
          "PCI DSS requires strong cryptography (MD5 not acceptable)",
          "NIST recommends against MD5 for any security applications",
          "Many security frameworks flag MD5 as high-risk vulnerability"
        ]
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between cryptographic usage of MD5 and
  acceptable non-security uses like file checksums or legacy compatibility.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Java.WeakHashMd5.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Java.WeakHashMd5.ast_enhancement()
      iex> enhancement.min_confidence
      0.6
      
      iex> enhancement = Rsolv.Security.Patterns.Java.WeakHashMd5.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "MethodInvocation"
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "MethodInvocation",
        crypto_analysis: %{
          check_method_name: true,
          messagedigest_methods: ["getInstance", "digest", "update"],
          check_algorithm_parameter: true,
          weak_algorithms: ["MD5", "md5"],
          check_variable_usage: true
        },
        algorithm_detection: %{
          check_string_literals: true,
          weak_algorithm_patterns: ["MD5", "md5"],
          check_variable_assignments: true,
          check_method_parameters: true,
          algorithm_variable_names: ["algorithm", "digest", "hash", "hashType", "digestType"]
        },
        method_analysis: %{
          check_method_names: true,
          md5_method_patterns: [
            "computeMD5",
            "calculateMD5",
            "generateMD5",
            "getMD5",
            "md5Hash",
            "createMD5"
          ],
          check_return_types: true,
          cryptographic_contexts: ["hash", "digest", "sign", "verify", "authenticate"]
        }
      },
      context_rules: %{
        check_cryptographic_context: true,
        high_risk_contexts: [
          "password hashing",
          "digital signatures",
          "authentication tokens",
          "session management",
          "API key generation",
          "certificate verification"
        ],
        acceptable_uses: %{
          # Still risky due to collision attacks
          file_checksums: false,
          # Should be upgraded
          legacy_compatibility: false,
          # Attackers can still exploit
          non_security_hashing: false,
          # SHA-256 is fast enough
          performance_critical: false
        },
        strong_algorithms: ["SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512"],
        password_libraries: ["BCrypt", "SCrypt", "Argon2", "PBKDF2"],
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/],
        check_variable_context: true
      },
      confidence_rules: %{
        base: 0.7,
        adjustments: %{
          "is_cryptographic_context" => 0.2,
          "has_security_variable_name" => 0.1,
          "in_authentication_code" => 0.2,
          "in_password_handling" => 0.3,
          # Still risky but lower priority
          "uses_checksum_only" => -0.2,
          "in_test_code" => -0.4,
          "is_commented_out" => -0.8,
          # Acknowledged technical debt
          "has_upgrade_comment" => -0.1
        }
      },
      min_confidence: 0.6
    }
  end
end
