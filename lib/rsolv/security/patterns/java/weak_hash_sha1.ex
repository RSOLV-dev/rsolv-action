defmodule Rsolv.Security.Patterns.Java.WeakHashSha1 do
  @moduledoc """
  Weak Cryptography - SHA1 pattern for Java code.

  Detects usage of SHA-1 hash algorithm which is cryptographically broken and vulnerable
  to collision attacks. SHA-1 should not be used for any security-sensitive purposes
  including password hashing, digital signatures, or data integrity verification.

  ## Vulnerability Details

  SHA-1 (Secure Hash Algorithm 1) is a cryptographic hash function that produces a 160-bit hash value.
  However, it is fundamentally broken due to its vulnerability to collision attacks, where
  attackers can create two different inputs that produce the same hash output. This breaks
  the fundamental property of cryptographic hash functions and makes SHA-1 unsuitable for
  security applications.

  The SLOTH (Security Losses from Obsolete and Truncated Transcript Hashes) attack
  demonstrates practical exploitation of SHA-1 weaknesses in TLS connections.

  ### Attack Example

  ```java
  // Vulnerable code
  MessageDigest md = MessageDigest.getInstance("SHA-1");
  String passwordHash = bytesToHex(md.digest(password.getBytes()));

  // Attack: SHA-1 collision allows creation of different passwords with same hash
  // SLOTH attack can exploit SHA-1 in TLS signature verification
  ```

  ## References

  - CWE-327: Use of a Broken or Risky Cryptographic Algorithm
  - OWASP A02:2021 - Cryptographic Failures
  - CVE-2015-7575: SLOTH Attack on SHA-1 signatures
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @impl true
  def pattern do
    %Pattern{
      id: "java-weak-hash-sha1",
      name: "Weak Cryptography - SHA1",
      description:
        "SHA-1 algorithm is cryptographically broken and vulnerable to collision attacks",
      type: :weak_crypto,
      severity: :medium,
      languages: ["java"],
      regex: [
        # MessageDigest.getInstance with SHA-1 - exclude comments
        ~r/^(?!.*\/\/).*MessageDigest\.getInstance\s*\(\s*[\"']SHA-1[\"']\s*\)/m,
        # String literals containing SHA-1 as algorithm - exclude comments
        ~r/^(?!.*\/\/).*[\"']SHA-1[\"']/m,
        # Method names containing SHA1
        ~r/(?:compute|calculate|generate|get)SHA1(?:Hash|Digest)?/i,
        # Variable assignments with SHA-1 - exclude comments
        ~r/^(?!.*\/\/).*(?:algorithm|digest|hash|hashType)\s*=\s*[\"']SHA-1[\"']/im,
        # SHA-1 in method calls - exclude comments
        ~r/^(?!.*\/\/).*\.(?:createHash|getDigest|hash)\s*\(\s*[\"']SHA-1[\"']/im,
        # Enum or constant references to SHA1
        ~r/HashAlgorithm\.SHA1|ALGORITHM_SHA1|SHA1_ALGORITHM|DigestType\.SHA_1/,
        # TLS and signature contexts with SHA-1
        ~r/SHA1withRSA|SHA1PRNG/
      ],
      cwe_id: "CWE-327",
      owasp_category: "A02:2021",
      recommendation: "Use SHA-256, SHA-3, or other secure hash algorithms instead of SHA-1",
      test_cases: %{
        vulnerable: [
          ~S|MessageDigest md = MessageDigest.getInstance("SHA-1");|,
          ~S|MessageDigest.getInstance("SHA-1").digest(password.getBytes());|,
          ~S|signatureAlgorithm = "SHA1withRSA";|,
          ~S|SecureRandom.getInstance("SHA1PRNG");|
        ],
        safe: [
          ~S|MessageDigest md = MessageDigest.getInstance("SHA-256");|,
          ~S|MessageDigest md = MessageDigest.getInstance("SHA3-256");|,
          ~S|signatureAlgorithm = "SHA256withRSA";|,
          ~S|// Using SHA-1 for backwards compatibility|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      SHA-1 (Secure Hash Algorithm 1) is a cryptographic hash function that produces
      a 160-bit hash value. However, SHA-1 is fundamentally broken and should never be
      used for security-sensitive purposes. The algorithm is vulnerable to collision
      attacks where attackers can create two different inputs that produce identical
      hash outputs.

      Key vulnerabilities of SHA-1:
      - Collision attacks demonstrated in practice (SHAttered attack, 2017)
      - SLOTH attack exploits SHA-1 weaknesses in TLS connections
      - Pre-image attacks are theoretically possible with sufficient computing power
      - Length extension attacks are possible in certain contexts
      - Not suitable for password hashing due to speed and collision vulnerabilities

      Common vulnerable usage patterns:
      - Password hashing and storage
      - Digital signature generation (SHA1withRSA)
      - TLS certificate verification
      - Session token generation
      - API key or token derivation
      - Random number generation (SHA1PRNG)
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
          id: "shattered_attack",
          title: "SHAttered: The first collision for full SHA-1",
          url: "https://shattered.io/"
        },
        %{
          type: :research,
          id: "sloth_attack_cve",
          title: "CVE-2015-7575: SLOTH Attack - Weak transcript hash vulnerability",
          url: "https://nvd.nist.gov/vuln/detail/CVE-2015-7575"
        },
        %{
          type: :research,
          id: "nist_sha1_deprecation",
          title: "NIST Policy on Hash Functions - SHA-1 Deprecation",
          url: "https://csrc.nist.gov/projects/hash-functions"
        }
      ],
      attack_vectors: [
        "Collision attack: Create two different files with the same SHA-1 hash",
        "SLOTH attack: Exploit SHA-1 weaknesses in TLS signature verification",
        "Certificate forgery: Generate rogue SSL certificates with colliding hashes",
        "Digital signature bypass: Create alternate documents with same signature",
        "Password hash collision: Find alternate passwords that hash to same value",
        "Session fixation: Generate predictable session tokens due to weak hashing"
      ],
      real_world_impact: [
        "Authentication bypass through password hash collisions",
        "Digital signature forgery enabling document tampering",
        "SSL/TLS certificate forgery for man-in-the-middle attacks",
        "Data integrity violations in file verification systems",
        "Session hijacking through predictable token generation",
        "Compliance violations (FIPS 140-2, Common Criteria prohibit SHA-1)",
        "Legal liability for using known-insecure cryptographic algorithms"
      ],
      cve_examples: [
        %{
          id: "CVE-2015-7575",
          description:
            "SLOTH - Weak SHA-1 signature hash vulnerability affecting TLS implementations",
          severity: "high",
          cvss: 7.1,
          note: "SHA-1 signature vulnerabilities in TLS connections enabling MitM attacks"
        },
        %{
          id: "CVE-2017-9233",
          description: "XML Digital Signature API allows SHA-1 which is cryptographically weak",
          severity: "medium",
          cvss: 5.9,
          note: "Allows attackers to spoof XML signatures using SHA-1 collision attacks"
        }
      ],
      detection_notes: """
      This pattern detects SHA-1 usage in various contexts:
      - MessageDigest.getInstance("SHA-1") calls
      - String literals containing "SHA-1" as algorithm identifiers
      - Method names containing SHA1 (computeSHA1, generateSHA1Hash, etc.)
      - Variable assignments where SHA-1 is specified as the algorithm
      - Method calls passing SHA-1 as hash algorithm parameter
      - Constants and enum references to SHA1 algorithms
      - TLS signature algorithms using SHA-1 (SHA1withRSA)
      - Random number generation using SHA1PRNG

      The pattern looks for both direct MessageDigest usage and indirect references
      to SHA-1 through variables, constants, and method parameters.
      """,
      safe_alternatives: [
        "Use SHA-256: MessageDigest.getInstance(\"SHA-256\") for general hashing",
        "Use SHA-3: MessageDigest.getInstance(\"SHA3-256\") for modern applications",
        "For passwords: Use BCrypt, scrypt, or Argon2 (not plain hashing)",
        "For HMAC: Use HMAC-SHA256 instead of HMAC-SHA1",
        "For digital signatures: Use SHA256withRSA or SHA256withECDSA",
        "For TLS: Use modern cipher suites with SHA-256 or higher",
        "For random numbers: Use SecureRandom.getInstanceStrong() instead of SHA1PRNG"
      ],
      additional_context: %{
        common_mistakes: [
          "Using SHA-1 for 'non-security' purposes (still vulnerable to intentional attacks)",
          "Believing SHA-1 is acceptable for internal systems (insider threats exist)",
          "Using SHA-1 for performance reasons (modern SHA algorithms are fast enough)",
          "Thinking collision resistance doesn't matter for their use case",
          "Using SHA1PRNG believing it's secure (it has known weaknesses)",
          "Using SHA1withRSA for new certificates (deprecated by most CAs)"
        ],
        secure_patterns: [
          "Always use SHA-256 or higher for any hashing needs",
          "Use proper password hashing libraries (BCrypt, Argon2)",
          "Implement crypto-agility to easily upgrade algorithms",
          "Use HMAC with secure hash functions for authentication",
          "Regularly review and update cryptographic implementations",
          "Use modern TLS cipher suites that exclude SHA-1"
        ],
        sloth_attack_details: [
          "SLOTH exploits transcript hash collisions in TLS handshakes",
          "Affects both client and server certificate authentication",
          "Can be used to impersonate servers or clients in TLS connections",
          "Mitigated by using SHA-256 or higher in TLS signature algorithms"
        ],
        compliance_considerations: [
          "FIPS 140-2 prohibits SHA-1 for cryptographic purposes",
          "PCI DSS requires strong cryptography (SHA-1 not acceptable)",
          "NIST recommends against SHA-1 for any security applications",
          "Browser vendors have deprecated SHA-1 certificates",
          "Many security frameworks flag SHA-1 as high-risk vulnerability"
        ]
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between cryptographic usage of SHA-1 and
  acceptable legacy uses, while maintaining high detection for security contexts.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Java.WeakHashSha1.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]

      iex> enhancement = Rsolv.Security.Patterns.Java.WeakHashSha1.ast_enhancement()
      iex> enhancement.min_confidence
      0.7

      iex> enhancement = Rsolv.Security.Patterns.Java.WeakHashSha1.ast_enhancement()
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
          weak_algorithms: ["SHA-1", "sha-1", "SHA1", "sha1"],
          check_variable_usage: true
        },
        algorithm_detection: %{
          check_string_literals: true,
          weak_algorithm_patterns: ["SHA-1", "sha-1", "SHA1", "sha1"],
          check_variable_assignments: true,
          check_method_parameters: true,
          algorithm_variable_names: [
            "algorithm",
            "digest",
            "hash",
            "hashType",
            "digestType",
            "signatureAlgorithm"
          ]
        },
        signature_analysis: %{
          check_signature_algorithms: true,
          weak_signature_patterns: ["SHA1withRSA", "SHA1withDSA", "SHA1withECDSA"],
          check_tls_contexts: true,
          random_number_patterns: ["SHA1PRNG"]
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
          "certificate verification",
          "TLS handshakes",
          "random number generation"
        ],
        acceptable_uses: %{
          # Git uses SHA-1 but attacks are possible
          git_checksums: false,
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
        base: 0.8,
        adjustments: %{
          "is_cryptographic_context" => 0.1,
          "has_security_variable_name" => 0.1,
          "in_authentication_code" => 0.1,
          "in_password_handling" => 0.2,
          "in_tls_context" => 0.2,
          "uses_signature_algorithm" => 0.2,
          "in_test_code" => -0.4,
          "is_commented_out" => -0.8,
          "has_upgrade_comment" => -0.1,
          # Still risky but lower priority
          "is_git_related" => -0.2
        }
      },
      min_confidence: 0.7
    }
  end
end
