defmodule RsolvApi.Security.Patterns.Elixir.WeakCryptoSha1 do
  @moduledoc """
  Detects usage of SHA1 hashing algorithm which is deprecated for security purposes.
  
  This pattern identifies instances where SHA1 is used for cryptographic purposes,
  which is insecure due to its vulnerability to collision attacks and NIST deprecation.
  
  ## Vulnerability Details
  
  SHA-1 (Secure Hash Algorithm 1) was designed as a cryptographic hash function but
  is now considered deprecated for security purposes. Key issues include:
  - Collision attacks: Practical attacks demonstrated (SHAttered, 2017)
  - NIST deprecation: Officially deprecated in 2011, retirement by 2030
  - Fast computation: Modern hardware can compute billions of SHA1 hashes per second
  - Erlang/OTP deprecation: ssh-rsa deprecated due to SHA1 usage
  
  ### Attack Example
  
  Vulnerable code:
  ```elixir
  # Password hashing with SHA1 - NEVER DO THIS!
  def hash_password(password) do
    :crypto.hash(:sha, password)
    |> Base.encode16()
  end
  
  # Token generation with SHA1 - INSECURE!
  def generate_token(user_id) do
    :crypto.hash(:sha, "\#{user_id}:\#{System.system_time()}")
    |> Base.encode16()
  end
  
  # HMAC with SHA1 - DEPRECATED!
  def sign_message(key, message) do
    :crypto.hmac(:sha, key, message)
  end
  ```
  
  An attacker could:
  - Generate hash collisions to bypass security checks
  - Crack SHA1 password hashes using rainbow tables
  - Exploit collision attacks like SHAttered
  - Predict or forge tokens/signatures
  
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
  
  # HMAC with SHA-256
  def sign_message(key, message) do
    :crypto.mac(:hmac, :sha256, key, message)
  end
  
  # For Git/checksums (where SHA1 might be acceptable)
  def git_hash(content) do
    # SHA1 is still used by Git for compatibility
    :crypto.hash(:sha, content)
  end
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "elixir-weak-crypto-sha1",
      name: "Weak Cryptography - SHA1",
      description: "SHA-1 is deprecated for security purposes and vulnerable to collision attacks",
      type: :weak_crypto,
      severity: :medium,
      languages: ["elixir"],
      regex: [
        # :crypto.hash(:sha, ...)
        ~r/:crypto\.hash\s*\(\s*:sha\b/,
        # :crypto.sha(...) - legacy function
        ~r/:crypto\.sha\s*\(/,
        # :erlang.sha(...) - legacy function
        ~r/:erlang\.sha\s*\(/,
        # Variable assignment with :sha
        ~r/=\s*:sha\b/,
        # Piped to crypto functions with sha
        ~r/\|>\s*:crypto\.hash\s*\(\s*:sha\b/,
        # SHA1 in function names (likely usage)
        ~r/def\s+\w*sha1?\w*\s*\(/i,
        # Crypto.hash with SHA1 (uppercase module alias)
        ~r/Crypto\.hash\s*\(\s*:sha\b/,
        # HMAC with SHA1
        ~r/:crypto\.hmac\s*\(\s*:sha\b/,
        # MAC with SHA1 (newer API)
        ~r/:crypto\.mac\s*\(\s*:hmac\s*,\s*:sha\b/
      ],
      default_tier: :public,
      cwe_id: "CWE-327",
      owasp_category: "A02:2021",
      recommendation: "Use :crypto.hash(:sha256, data) or stronger algorithms. For passwords use Argon2/Bcrypt.",
      test_cases: %{
        vulnerable: [
          ":crypto.hash(:sha, password)",
          "Base.encode16(:crypto.hash(:sha, data))",
          ":crypto.sha(data)",
          ":erlang.sha(content)",
          "algorithm = :sha\n:crypto.hash(algorithm, data)",
          "data |> :crypto.hash(:sha, _)",
          ":crypto.hmac(:sha, key, message)"
        ],
        safe: [
          ":crypto.hash(:sha256, data)",
          ":crypto.hash(:sha512, data)",
          ":crypto.hash(:blake2b, data)"
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      SHA-1 (Secure Hash Algorithm 1) is a cryptographic hash function that produces a 160-bit
      hash value. However, SHA-1 is now considered broken for security applications due to
      vulnerability to collision attacks and has been officially deprecated by NIST.
      
      In the Elixir/Erlang ecosystem, SHA-1 is available through :crypto.hash(:sha, data),
      :crypto.sha/1, :erlang.sha/1, and HMAC functions. The BEAM VM's efficiency actually
      makes SHA-1 even less suitable for security purposes where slow computation is desirable.
      
      Key deprecation milestones:
      - 2011: NIST officially deprecated SHA-1 for security purposes
      - 2017: Google/CWI demonstrated practical collision attacks (SHAttered)
      - OTP-24: Erlang/OTP deprecated ssh-rsa due to SHA-1 usage
      - 2030: NIST complete retirement deadline
      
      SHA-1 should never be used for:
      - Password hashing or storage
      - Digital signatures or certificates
      - Cryptographic authentication
      - Session tokens or API keys
      - HMAC for security purposes
      - Any security-critical application
      
      Note: SHA-1 may still be acceptable for non-security purposes like Git commits,
      file checksums, or legacy compatibility where collision resistance is not critical.
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
          title: "SHAttered: The First Collision for Full SHA-1",
          url: "https://shattered.io/"
        },
        %{
          type: :nist,
          id: "nist_sha1_retirement",
          title: "NIST Retires SHA-1 Cryptographic Algorithm",
          url: "https://www.nist.gov/news-events/news/2022/12/nist-retires-sha-1-cryptographic-algorithm"
        },
        %{
          type: :research,
          id: "erlang_otp_deprecation",
          title: "Erlang/OTP Deprecations - ssh-rsa",
          url: "https://www.erlang.org/doc/deprecations.html"
        }
      ],
      attack_vectors: [
        "Collision attacks to create different inputs with same hash (SHAttered)",
        "Birthday attacks requiring only 2^63 operations (practical)",
        "Rainbow table attacks on SHA-1 password hashes",
        "GPU-accelerated brute force attacks (billions of hashes/second)",
        "Precomputed hash databases for common passwords",
        "Chosen-prefix attacks for forged certificates/signatures",
        "Length extension attacks in certain HMAC constructions"
      ],
      real_world_impact: [
        "Google/CWI demonstrated practical SHA-1 collisions (2017)",
        "Forged digital certificates using SHA-1 collisions (Flame malware)",
        "Git repository integrity attacks via SHA-1 collisions",
        "Password databases compromised through SHA-1 rainbow tables",
        "Authentication bypass through hash collision vulnerabilities",
        "SSL/TLS certificate forgery via collision attacks",
        "Erlang/OTP ssh-rsa deprecation due to SHA-1 vulnerabilities"
      ],
      cve_examples: [
        %{
          id: "CVE-2019-14855",
          description: "OpenSSH SHA-1 deprecation and security implications",
          severity: "medium",
          cvss: 5.9,
          note: "Related to SSH key algorithms using SHA-1, similar to Erlang/OTP ssh-rsa deprecation"
        },
        %{
          id: "CVE-2017-15361",
          description: "SHA-1 collision attack demonstration (SHAttered)",
          severity: "high",
          cvss: 7.5,
          note: "Practical demonstration that SHA-1 collisions are feasible"
        }
      ],
      detection_notes: """
      This pattern detects:
      - Direct calls to :crypto.hash(:sha, ...)
      - Legacy :crypto.sha/1 function usage
      - Erlang's :erlang.sha/1 function
      - Variable assignments with :sha atom
      - Piped data to SHA-1 functions
      - Function names containing 'sha1' or 'sha'
      - HMAC usage with SHA-1 (:crypto.hmac(:sha, ...))
      - MAC usage with SHA-1 (:crypto.mac(:hmac, :sha, ...))
      """,
      safe_alternatives: [
        "Use Argon2 for password hashing: Argon2.hash_pwd_salt/1",
        "Use Bcrypt for password hashing: Bcrypt.hash_pwd_salt/1", 
        "Use SHA-256 for general hashing: :crypto.hash(:sha256, data)",
        "Use SHA-512 for higher security: :crypto.hash(:sha512, data)",
        "Use BLAKE2 for performance: :crypto.hash(:blake2b, data)",
        "For HMAC: :crypto.mac(:hmac, :sha256, key, data)",
        "For SHA-3: :crypto.hash(:sha3_256, data)",
        "For Git/checksums only (non-security): SHA-1 may be acceptable"
      ],
      additional_context: %{
        common_mistakes: [
          "Using SHA-1 for password storage",
          "Thinking HMAC-SHA-1 is secure (it's deprecated)",
          "Using SHA-1 for API key generation",
          "Assuming Git's SHA-1 usage means it's secure for other purposes",
          "Double-hashing with SHA-1 for 'extra security'",
          "Using SHA-1 in digital signatures or certificates"
        ],
        secure_patterns: [
          "Always use proper password hashing libraries (Argon2, Bcrypt)",
          "Use SHA-256 or SHA-3 for cryptographic hashing",
          "Follow NIST recommendations for hash algorithm selection",
          "Consider the specific use case (security vs compatibility)",
          "Keep up with cryptographic algorithm deprecation schedules"
        ],
        legitimate_uses: [
          "Git commit hashes (for compatibility)",
          "Non-security file checksums",
          "Legacy system compatibility",
          "P2P protocol compatibility (BitTorrent, etc.)"
        ]
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between security-critical SHA-1 usage
  and legitimate non-security uses like Git operations or checksums.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Elixir.WeakCryptoSha1.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Elixir.WeakCryptoSha1.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        crypto_analysis: %{
          check_crypto_module: true,
          crypto_functions: ["hash", "sha", "hmac", "mac"],
          hash_algorithms: [":sha", "sha", ":sha1", "sha1"],
          check_algorithm_usage: true
        },
        context_analysis: %{
          check_variable_names: true,
          security_indicators: ["password", "pwd", "secret", "token", "key", "auth",
                               "credential", "session", "api_key", "private", "sign", "verify"],
          git_indicators: ["git", "commit", "blob", "tree", "repo", "revision"],
          checksum_indicators: ["checksum", "hash", "digest", "fingerprint", "etag", "integrity"]
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/_test\.exs$/, ~r/benchmarks/],
        legitimate_uses: ["git", "checksum", "file_integrity", "cache_key", "etag", 
                         "non_cryptographic", "legacy_compatibility", "torrent", "p2p"],
        security_contexts: ["password", "authentication", "token", "session", "api", 
                           "signature", "certificate", "hmac"],
        exclude_if_git: true,
        exclude_if_checksum: true
      },
      confidence_rules: %{
        base: 0.6,
        adjustments: %{
          "in_security_context" => 0.3,
          "git_usage" => -0.7,
          "checksum_usage" => -0.5,
          "in_test_code" => -1.0,
          "password_related" => 0.4,
          "legacy_code_comment" => -0.3,
          "file_operation" => -0.4,
          "p2p_protocol" => -0.6
        }
      },
      min_confidence: 0.7
    }
  end
end