defmodule RsolvApi.Security.Patterns.Ruby.WeakCryptoMd5 do
  @moduledoc """
  Pattern for detecting weak MD5 cryptographic hash usage in Ruby applications.
  
  This pattern identifies when MD5 is used for cryptographic purposes such as
  password hashing or data integrity. MD5 is considered cryptographically broken
  due to collision vulnerabilities and should not be used for security purposes.
  
  ## Vulnerability Details
  
  MD5 (Message-Digest Algorithm 5) was once widely used for cryptographic hashing
  but has been considered insecure since 2004 when researchers demonstrated practical
  collision attacks. Using MD5 for passwords, digital signatures, or any security-critical
  application puts data at risk.
  
  ### Attack Example
  ```ruby
  # Vulnerable password storage
  password_hash = Digest::MD5.hexdigest(password)
  User.create(password_hash: password_hash)
  
  # Attack: Rainbow tables, collision attacks
  # Result: Passwords can be cracked in seconds
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "ruby-weak-crypto-md5",
      name: "Weak Cryptography - MD5 Usage",
      description: "Detects usage of weak MD5 hash algorithm",
      type: :cryptographic_failure,
      severity: :medium,
      languages: ["ruby"],
      regex: [
        ~r/Digest::MD5/,
        ~r/OpenSSL::Digest(?:\.new\(['"]MD5['"]\)|::MD5)/,
        ~r/\.md5\s*\(/
      ],
      default_tier: :public,
      cwe_id: "CWE-328",
      owasp_category: "A02:2021",
      recommendation: "Use SHA-256 or SHA-384 for cryptographic hashing. For password hashing, use bcrypt.",
      test_cases: %{
        vulnerable: [
          ~S|Digest::MD5.hexdigest(password)|,
          ~S|OpenSSL::Digest.new('MD5')|,
          ~S|require 'digest'
hash = Digest::MD5.hexdigest(data)|
        ],
        safe: [
          ~S|Digest::SHA256.hexdigest(data)|,
          ~S|BCrypt::Password.create(password)|,
          ~S|OpenSSL::Digest.new('SHA256')|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      MD5 (Message-Digest Algorithm 5) is a widely used cryptographic hash function
      that produces a 128-bit hash value. However, MD5 has been cryptographically
      broken and is unsuitable for security purposes due to extensive vulnerabilities.
      
      The primary issues with MD5 include:
      - **Collision attacks**: Two different inputs can produce the same hash
      - **Speed**: MD5 is too fast, making brute-force attacks feasible
      - **Rainbow tables**: Pre-computed hash databases can crack MD5 passwords quickly
      - **Length extension attacks**: Attackers can append data to messages
      
      Historical breaches involving MD5:
      - 2012 LinkedIn breach: 6.5 million MD5 passwords cracked
      - 2013 Adobe breach: 150 million MD5 passwords exposed
      - Flame malware used MD5 collision to forge Microsoft certificates
      
      MD5 should never be used for:
      - Password storage
      - Digital signatures
      - SSL certificates
      - Any cryptographic purpose
      
      Limited acceptable uses (non-security):
      - File checksums for accidental corruption detection
      - Non-cryptographic hashing (like hash tables)
      - Legacy system compatibility (with migration plan)
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-328",
          title: "Use of Weak Hash",
          url: "https://cwe.mitre.org/data/definitions/328.html"
        },
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
          id: "md5_collision_2004",
          title: "How to Break MD5 and Other Hash Functions",
          url: "https://www.iacr.org/archive/eurocrypt2005/34940019/34940019.pdf"
        }
      ],
      attack_vectors: [
        "Rainbow table attacks: Pre-computed hash lookups",
        "Collision attacks: Generate two inputs with same MD5 hash",
        "Birthday attacks: Find collisions in 2^64 operations",
        "Brute force: Modern GPUs can test billions of hashes/second",
        "Length extension attacks: Append data without knowing original",
        "Chosen-prefix collisions: Forge certificates and signatures",
        "Google SHA-1 collision technique adapted to MD5",
        "HashClash tool for automated collision generation"
      ],
      real_world_impact: [
        "2012 LinkedIn: 6.5M unsalted MD5 passwords cracked in days",
        "2013 Adobe: 150M MD5 passwords exposed, millions cracked",
        "2008 Flame malware: Used MD5 collision to forge MS certificate",
        "2004 MD5 CAs: Rogue CA certificates created via collisions",
        "eCommerce fraud via MD5 payment hash manipulation",
        "Source code tampering with matching MD5 checksums",
        "Authentication bypass through MD5 collision attacks"
      ],
      cve_examples: [
        %{
          id: "CVE-2008-4108",
          description: "MD5 collision in CA certificate issuance",
          severity: "high",
          cvss: 7.5,
          note: "Allowed creation of rogue CA certificates"
        },
        %{
          id: "CVE-2015-7575",
          description: "SLOTH attack on TLS using MD5",
          severity: "medium",
          cvss: 5.9,
          note: "TLS transcript collision attacks"
        },
        %{
          id: "LinkedIn-2012",
          description: "LinkedIn password breach with unsalted MD5",
          severity: "critical", 
          cvss: 9.0,
          note: "6.5 million passwords cracked due to weak hashing"
        },
        %{
          id: "Adobe-2013",
          description: "Adobe breach exposed 150M MD5 passwords",
          severity: "critical",
          cvss: 9.0,
          note: "Massive password exposure with weak encryption"
        }
      ],
      detection_notes: """
      This pattern detects MD5 usage through:
      - Digest::MD5 constant references
      - OpenSSL::Digest with MD5 parameter
      - Method calls to .md5()
      
      The pattern may have false positives for:
      - Non-security uses like checksums
      - Legacy code under migration
      - Test fixtures and examples
      """,
      safe_alternatives: [
        "Password hashing: Use BCrypt::Password.create(password)",
        "Password hashing: Use Argon2::Password.create(password)",
        "General hashing: Use Digest::SHA256 or SHA384",
        "HMAC: Use OpenSSL::HMAC with SHA-256",
        "File integrity: Use SHA-256 checksums",
        "Unique IDs: Use SecureRandom.uuid",
        "For legacy systems: Add salt and migrate to bcrypt",
        "Key derivation: Use PBKDF2, scrypt, or Argon2"
      ],
      additional_context: %{
        common_mistakes: [
          "Using MD5 for password storage",
          "Believing salted MD5 is secure",
          "Using MD5 for API tokens or session IDs",
          "Trusting MD5 for file integrity in security contexts",
          "Double-hashing with MD5 thinking it's more secure"
        ],
        secure_patterns: [
          "BCrypt::Password.create(password, cost: 12)",
          "Argon2::Password.create(password)",
          "Digest::SHA256.hexdigest(data)",
          "OpenSSL::HMAC.hexdigest('SHA256', key, data)",
          "ActiveSupport::MessageEncryptor for encryption"
        ],
        migration_guide: [
          "Identify all MD5 usage in codebase",
          "Separate security from non-security uses",
          "Implement bcrypt for new passwords",
          "Force password reset on next login",
          "Update password on successful MD5 match"
        ]
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between security-critical MD5 usage
  and acceptable non-cryptographic uses like checksums.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.WeakCryptoMd5.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.WeakCryptoMd5.ast_enhancement()
      iex> enhancement.min_confidence
      0.6
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "ConstantAccess",
        module_patterns: ["Digest", "OpenSSL", "Crypto"],
        constant_names: ["MD5", "Md5"],
        method_analysis: %{
          check_receiver: true,
          method_names: ["hexdigest", "digest", "base64digest", "new"]
        }
      },
      context_rules: %{
        exclude_paths: [
          ~r/test/,
          ~r/spec/,
          ~r/fixtures/,
          ~r/examples/,
          ~r/db\/migrate/
        ],
        check_usage_context: true,
        non_security_contexts: [
          "checksum",
          "etag",
          "cache_key",
          "content_md5",
          "file_hash",
          "non_cryptographic"
        ],
        security_indicators: [
          "password",
          "secret",
          "token",
          "auth",
          "session",
          "cookie",
          "signature"
        ]
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "has_security_indicator" => 0.4,
          "in_auth_context" => 0.3,
          "password_related" => 0.5,
          "in_model_file" => 0.2,
          "has_non_security_marker" => -0.6,
          "in_migration" => -0.3,
          "in_test_code" => -1.0
        }
      },
      min_confidence: 0.6
    }
  end
end