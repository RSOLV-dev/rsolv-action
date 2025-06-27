defmodule RsolvApi.Security.Patterns.Elixir.WeakCryptoMd5 do
  @moduledoc """
  Detects usage of MD5 hashing algorithm which is cryptographically broken.
  
  This pattern identifies instances where MD5 is used for cryptographic purposes,
  which is insecure due to its vulnerability to collision attacks and fast computation.
  
  ## Vulnerability Details
  
  MD5 (Message Digest Algorithm 5) was designed as a cryptographic hash function but
  is now considered broken for security purposes. Its vulnerabilities include:
  - Collision attacks: Finding two different inputs that produce the same hash
  - Fast computation: Modern hardware can compute billions of MD5 hashes per second
  - Preimage attacks: In some cases, finding an input that produces a specific hash
  
  ### Attack Example
  
  Vulnerable code:
  ```elixir
  # Password hashing with MD5 - NEVER DO THIS!
  def hash_password(password) do
    :crypto.hash(:md5, password)
    |> Base.encode16()
  end
  
  # API key generation with MD5 - INSECURE!
  def generate_api_key(user_id) do
    :crypto.hash(:md5, "\#{user_id}:\#{System.system_time()}")
    |> Base.encode16()
  end
  ```
  
  An attacker could:
  - Crack MD5 password hashes using rainbow tables or brute force
  - Generate hash collisions to bypass security checks
  - Predict or forge API keys
  
  ### Safe Alternative
  
  Safe code:
  ```elixir
  # Password hashing with Argon2 (recommended)
  def hash_password(password) do
    Argon2.hash_pwd_salt(password)
  end
  
  # For general hashing (non-passwords)
  def hash_data(data) do
    :crypto.hash(:sha256, data)
  end
  
  # For checksums (where MD5 might be acceptable)
  def file_checksum(content) do
    # MD5 is OK for non-security checksums
    :crypto.hash(:md5, content)
  end
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "elixir-weak-crypto-md5",
      name: "Weak Cryptography - MD5",
      description: "MD5 is cryptographically broken and should not be used for security",
      type: :weak_crypto,
      severity: :medium,
      languages: ["elixir"],
      regex: [
        # :crypto.hash(:md5, ...)
        ~r/:crypto\.hash\s*\(\s*:md5/,
        # :crypto.md5(...)
        ~r/:crypto\.md5\s*\(/,
        # :erlang.md5(...)
        ~r/:erlang\.md5\s*\(/,
        # Variable assignment with :md5
        ~r/=\s*:md5\b/,
        # Piped to crypto functions with md5
        ~r/\|>\s*:crypto\.hash\s*\(\s*:md5/,
        # MD5 in function names (likely usage)
        ~r/def\s+\w*md5\w*\s*\(/i,
        # Crypto.hash with MD5 (uppercase module alias)
        ~r/Crypto\.hash\s*\(\s*:md5/
      ],
      cwe_id: "CWE-327",
      owasp_category: "A02:2021",
      recommendation: "Use :crypto.hash(:sha256, data) or Argon2/Bcrypt for passwords",
      test_cases: %{
        vulnerable: [
          ~S|:crypto.hash(:md5, password)|,
          ~S|Base.encode16(:crypto.hash(:md5, data))|,
          ~S|:crypto.md5(data)|,
          ~S|:erlang.md5(content)|,
          ~S|algorithm = :md5
:crypto.hash(algorithm, data)|,
          "data |> :crypto.hash(:md5, _)"
        ],
        safe: [
          ~S|:crypto.hash(:sha256, data)|,
          ~S|Argon2.hash_pwd_salt(password)|,
          ~S|Bcrypt.hash_pwd_salt(password)|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      MD5 (Message Digest Algorithm 5) is a widely known cryptographic hash function that
      produces a 128-bit hash value. However, MD5 is no longer considered secure against
      well-funded opponents due to its vulnerability to collision attacks.
      
      In the Elixir/Erlang ecosystem, MD5 is available through :crypto.hash(:md5, data),
      :crypto.md5/1, and :erlang.md5/1. While it may still be acceptable for non-security
      purposes like checksums, it should never be used for:
      - Password hashing
      - Digital signatures
      - Cryptographic authentication
      - Session tokens or API keys
      - Any security-critical application
      
      The BEAM VM makes it easy to compute MD5 hashes quickly, which ironically makes
      MD5 even less suitable for password hashing where slow computation is desirable.
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
          id: "md5_collision_2004",
          title: "How to Break MD5 and Other Hash Functions",
          url: "https://www.iacr.org/archive/eurocrypt2005/34940019/34940019.pdf"
        },
        %{
          type: :research,
          id: "md5_vulnerabilities",
          title: "MD5 Vulnerabilities - RFC 6151",
          url: "https://datatracker.ietf.org/doc/html/rfc6151"
        }
      ],
      attack_vectors: [
        "Rainbow table attacks on MD5 password hashes",
        "Collision attacks to create different inputs with same hash",
        "Birthday attacks requiring only 2^64 operations",
        "GPU-based brute force attacks (billions of hashes/second)",
        "Precomputed hash databases for common passwords",
        "Length extension attacks in certain constructions"
      ],
      real_world_impact: [
        "Password databases compromised through MD5 rainbow tables",
        "Forged digital certificates using MD5 collisions (2008)",
        "Malware signed with legitimate certificates via collision",
        "Authentication bypass through hash collision",
        "Session hijacking via predictable tokens",
        "API key forgery in systems using MD5 for key generation"
      ],
      cve_examples: [
        %{
          id: "CVE-2012-2146",
          description: "Python-elixir weak use of crypto (MD5) for encryption",
          severity: "high",
          cvss: 7.5,
          note: "Shows how MD5 misuse can lead to information disclosure"
        },
        %{
          id: "CVE-2008-5671",
          description: "MD5 collision attack on SSL certificates",
          severity: "critical",
          cvss: 10.0,
          note: "Demonstrated practical collision attacks against MD5"
        }
      ],
      detection_notes: """
      This pattern detects:
      - Direct calls to :crypto.hash(:md5, ...)
      - Legacy :crypto.md5/1 function usage
      - Erlang's :erlang.md5/1 function
      - Variable assignments with :md5 atom
      - Piped data to MD5 functions
      - Function names containing 'md5'
      """,
      safe_alternatives: [
        "Use Argon2 for password hashing: Argon2.hash_pwd_salt/1",
        "Use Bcrypt for password hashing: Bcrypt.hash_pwd_salt/1",
        "Use SHA-256 for general hashing: :crypto.hash(:sha256, data)",
        "Use SHA-512 for higher security: :crypto.hash(:sha512, data)",
        "Use BLAKE2 for performance: :crypto.hash(:blake2b, data)",
        "For HMAC: :crypto.mac(:hmac, :sha256, key, data)",
        "For checksums only (non-security): MD5 may be acceptable"
      ],
      additional_context: %{
        common_mistakes: [
          "Using MD5 for password storage",
          "Thinking salted MD5 is secure (it's not)",
          "Using MD5 for API key generation",
          "Double-hashing with MD5 for 'extra security'",
          "Using MD5 in HMAC thinking it's safe"
        ],
        secure_patterns: [
          "Always use proper password hashing libraries",
          "Use SHA-256 or better for cryptographic hashing",
          "Consider the specific use case when choosing algorithms",
          "Keep up with current cryptographic recommendations"
        ]
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between security-critical MD5 usage
  and legitimate non-security uses like checksums.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Elixir.WeakCryptoMd5.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Elixir.WeakCryptoMd5.ast_enhancement()
      iex> enhancement.min_confidence
      0.6
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        crypto_analysis: %{
          check_crypto_module: true,
          crypto_functions: ["hash", "md5"],
          hash_algorithms: [":md5", "md5"],
          check_algorithm_usage: true
        },
        context_analysis: %{
          check_variable_names: true,
          security_indicators: ["password", "pwd", "secret", "token", "key", "auth",
                               "credential", "session", "api_key", "private"],
          checksum_indicators: ["checksum", "hash", "digest", "fingerprint", "etag"]
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/_test\.exs$/, ~r/benchmarks/],
        legitimate_uses: ["checksum", "file_integrity", "cache_key", "etag", 
                         "non_cryptographic", "legacy_compatibility"],
        security_contexts: ["password", "authentication", "token", "session", "api"],
        exclude_if_checksum: true
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "in_security_context" => 0.4,
          "checksum_usage" => -0.6,
          "in_test_code" => -1.0,
          "password_related" => 0.5,
          "legacy_code_comment" => -0.3,
          "file_operation" => -0.4
        }
      },
      min_confidence: 0.6
    }
  end
end
