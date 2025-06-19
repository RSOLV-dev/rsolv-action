defmodule RsolvApi.Security.Patterns.Ruby.WeakRandom do
  @moduledoc """
  Pattern for detecting weak random number generation in Ruby applications.
  
  This pattern identifies when applications use cryptographically weak random
  number generators like rand(), Random.rand(), or srand() for security-sensitive
  operations such as generating tokens, session IDs, passwords, or API keys.
  
  ## Vulnerability Details
  
  Weak random number generation occurs when applications use predictable or
  insufficient random number generators for security-critical purposes. Ruby's
  built-in rand() and Random.rand() functions use the Mersenne Twister algorithm,
  which is statistically strong but cryptographically weak and predictable.
  
  ### Attack Example
  ```ruby
  # Vulnerable session token generation
  class SessionController < ApplicationController
    def create_session
      # VULNERABLE: Using weak rand for session token
      session_token = rand(10**16).to_s(36)  # Predictable sequence
      session[:token] = session_token
      cookies[:session_id] = session_token
      
      # VULNERABLE: API key generation with weak randomness
      api_key = (0...32).map { rand(65..90).chr }.join  # Mersenne Twister
      
      # VULNERABLE: Password reset token
      reset_token = rand(2**64).to_s(16)  # Predictable with known seed
      
      user.update(api_key: api_key, reset_token: reset_token)
    end
  end
  
  # Attack scenario: If attacker can predict the seed or observe sequence,
  # they can predict future "random" values and hijack sessions/accounts
  ```
  
  **Safe Alternative:**
  ```ruby
  # SECURE: Using SecureRandom for cryptographic purposes
  session_token = SecureRandom.hex(32)        # Cryptographically secure
  api_key = SecureRandom.urlsafe_base64(32)   # Unpredictable
  reset_token = SecureRandom.uuid             # Industry standard
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "ruby-weak-random",
      name: "Weak Random Number Generation",
      description: "Detects use of predictable random number generators for security-sensitive operations",
      type: :cryptographic_failure,
      severity: :medium,
      languages: ["ruby"],
      regex: [
        ~r/(?<!SecureRandom\.)\brand\s*\(/,  # rand(n) but not SecureRandom.rand or related methods
        ~r/\bRandom\.rand/,                 # Random.rand calls (not SecureRandom.random_*)
        ~r/\bsrand\b/,                      # srand seeding (with or without parentheses)
        ~r/Kernel\.rand/                    # Kernel.rand explicit calls
      ],
      cwe_id: "CWE-330",
      owasp_category: "A02:2021",
      recommendation: "Use SecureRandom.hex(), SecureRandom.uuid(), or SecureRandom.urlsafe_base64() for cryptographic purposes",
      test_cases: %{
        vulnerable: [
          ~S|token = rand(100000)|,
          ~S|session_id = Random.rand(10**8)|,
          ~S|password_reset = (0...8).map { rand(65..90).chr }.join|,
          ~S|api_key = rand(2**32).to_s(16)|,
          ~S|srand(Time.now.to_i)|,
          ~S|Kernel.rand(1000)|
        ],
        safe: [
          ~S|token = SecureRandom.hex(16)|,
          ~S|session_id = SecureRandom.uuid|,
          ~S|password_reset = SecureRandom.urlsafe_base64(12)|,
          ~S|api_key = SecureRandom.base64(32)|,
          ~S|SecureRandom.random_bytes(16)|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Weak random number generation is a cryptographic vulnerability that occurs when
      applications use predictable or statistically weak random number generators for
      security-sensitive operations. This vulnerability can lead to session hijacking,
      authentication bypass, and cryptographic attacks.
      
      **How Weak Random Generation Works:**
      Ruby's built-in random functions (rand, Random.rand) use the Mersenne Twister
      algorithm, which is excellent for statistical applications but inappropriate for
      cryptographic use because:
      - **Predictable Sequence**: Given enough observed values, future values can be predicted
      - **Seed Vulnerability**: If the seed is known or guessable, entire sequence is compromised
      - **State Recovery**: Internal state can be recovered from 624 consecutive outputs
      - **Reproducible**: Same seed always produces same sequence across Ruby versions
      
      **Ruby-Specific Vulnerabilities:**
      The GitHub Security Lab research identified CWE-338 vulnerabilities in Ruby applications
      where developers used rand() for security tokens. The Mersenne Twister period of 2^19937-1
      provides statistical strength but zero cryptographic security.
      
      **Critical Security Impact:**
      - **Session Hijacking**: Predictable session tokens allow account takeover
      - **API Key Prediction**: Weak API keys can be brute-forced or predicted
      - **Password Reset Bypass**: Predictable reset tokens enable unauthorized access
      - **CSRF Token Bypass**: Weak CSRF tokens can be predicted and bypassed
      - **Authentication Bypass**: Predictable challenge tokens compromise auth flows
      
      **Common Vulnerable Patterns:**
      - Using rand() for session IDs, API keys, or authentication tokens
      - Seeding with predictable values (timestamps, PIDs, simple integers)
      - Generating passwords or passphrases with weak randomness
      - Creating cryptographic nonces or initialization vectors
      - Building security tokens for password resets or email verification
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-330",
          title: "Use of Insufficiently Random Values",
          url: "https://cwe.mitre.org/data/definitions/330.html"
        },
        %{
          type: :cwe,
          id: "CWE-338",
          title: "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
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
          id: "fluidattacks_ruby_random",
          title: "FluidAttacks - Insecure Generation of Random Numbers in Ruby",
          url: "https://help.fluidattacks.com/portal/en/kb/articles/criteria-fixes-ruby-034"
        },
        %{
          type: :research,
          id: "github_security_lab_ruby",
          title: "GitHub Security Lab - Ruby Insecure Randomness Query",
          url: "https://github.com/github/securitylab/issues/795"
        },
        %{
          type: :research,
          id: "securerandom_vs_rand",
          title: "What is so 'secure' about SecureRandom?",
          url: "https://medium.com/@christ.blais/what-is-so-secure-about-securerandom-776254f1ce1c"
        },
        %{
          type: :research,
          id: "ruby_securerandom_docs",
          title: "Ruby SecureRandom Documentation",
          url: "https://docs.ruby-lang.org/en/3.1/SecureRandom.html"
        }
      ],
      attack_vectors: [
        "Sequence prediction: Observe multiple rand() outputs to predict future values",
        "Seed guessing: Predict rand() sequence by guessing seed (timestamps, PIDs)",
        "State recovery: Recover Mersenne Twister internal state from 624 outputs",
        "Brute force: Limited keyspace allows exhaustive search of weak tokens",
        "Timing attacks: Correlate token generation time with predictable seeds",
        "Session hijacking: Predict session tokens to impersonate users",
        "API key enumeration: Generate valid API keys through sequence prediction",
        "Password reset bypass: Predict reset tokens for unauthorized access",
        "CSRF bypass: Predict CSRF tokens to perform unauthorized actions",
        "Race conditions: Exploit predictable randomness in concurrent token generation"
      ],
      real_world_impact: [
        "GitHub Security Lab research: Ruby applications vulnerable to CWE-338 attacks",
        "FluidAttacks findings: Widespread use of rand() for security tokens in Ruby apps",
        "CVE-2011-2686: Ruby random number generator DoS through improper forking",
        "CVE-2008-2108: SSL library weak random generation with only 65,536 unique keys",
        "CVE-2019-25061: Cryptographically weak PRNG increasing prediction vulnerability",
        "Session token prediction attacks in Ruby on Rails applications",
        "API key compromise through weak random generation in Ruby microservices",
        "Authentication bypass in Ruby applications using predictable challenge tokens"
      ],
      cve_examples: [
        %{
          id: "CVE-2019-25061",
          description: "Cryptographically weak pseudo-random number generator vulnerability",
          severity: "medium",
          cvss: 5.3,
          note: "Ruby applications using weak PRNG for security-sensitive values"
        },
        %{
          id: "CVE-2011-2686",
          description: "Ruby random number generator denial of service through improper forking",
          severity: "medium", 
          cvss: 4.3,
          note: "Improper initialization of random generator in forked processes"
        },
        %{
          id: "CVE-2008-2108",
          description: "SSL library weak random generation with limited keyspace",
          severity: "high",
          cvss: 7.5,
          note: "Only 65,536 unique keys due to insufficient precision in random generation"
        }
      ],
      detection_notes: """
      This pattern detects weak random number generation by identifying Ruby's
      built-in random functions that are inappropriate for cryptographic use:
      
      **Primary Detection Points:**
      - rand() function calls: Global Kernel method for basic randomness
      - Random.rand(): Class method calls on Random class
      - srand() seeding: Setting predictable seeds makes randomness even weaker
      - Kernel.rand(): Explicit namespace calls to weak random function
      
      **Context-Aware Detection:**
      The AST enhancement analyzes usage context to reduce false positives:
      - **Security Context**: Detects when rand() is used for tokens, keys, sessions
      - **Variable Names**: Identifies security-related variable names (token, key, session)
      - **Assignment Context**: Checks if random values are assigned to security variables
      - **Method Context**: Analyzes containing methods for authentication/session logic
      
      **False Positive Considerations:**
      - Non-security uses (games, simulations, testing) are lower priority
      - Comments and documentation containing "rand" should be excluded
      - Test files using rand() for fixtures are generally safe
      - Math/statistical operations using rand() may be acceptable
      
      **Ruby-Specific Patterns:**
      - Range mapping: (0...n).map { rand(65..90).chr }.join for string generation
      - Base conversion: rand(n).to_s(36) for alphanumeric tokens
      - Mathematical operations: rand(2**32) for large number generation
      - Seeding patterns: srand(Time.now.to_i) or srand(Process.pid)
      """,
      safe_alternatives: [
        "SecureRandom.hex(16) - Generate hexadecimal token with 128 bits entropy",
        "SecureRandom.uuid - Generate RFC 4122 compliant UUID",
        "SecureRandom.urlsafe_base64(32) - Generate URL-safe base64 token",
        "SecureRandom.random_bytes(16) - Generate raw random bytes",
        "SecureRandom.base64(24) - Generate base64-encoded random string",
        "SecureRandom.alphanumeric(20) - Generate alphanumeric string (Ruby 3.1+)",
        "BCrypt::Password.create(password) - Use bcrypt for password hashing with salt",
        "Digest::SHA256.hexdigest(SecureRandom.random_bytes(32)) - Hashed random value"
      ],
      additional_context: %{
        common_mistakes: [
          "Using rand() for session tokens, API keys, or passwords",
          "Believing rand() is 'random enough' for security purposes", 
          "Seeding srand() with predictable values like timestamps",
          "Not understanding the difference between statistical and cryptographic randomness",
          "Using rand() in production while SecureRandom in development/testing",
          "Thinking larger ranges (rand(2**64)) provide security",
          "Using rand() for CSRF tokens or password reset codes",
          "Not considering that rand() sequences are reproducible across Ruby versions"
        ],
        secure_patterns: [
          "SecureRandom.hex(32) # 256-bit hexadecimal token",
          "SecureRandom.uuid # RFC 4122 UUID (128-bit)",
          "SecureRandom.urlsafe_base64(32) # URL-safe base64 token",
          "SecureRandom.random_bytes(16) # Raw 128-bit random bytes",
          "session[:csrf_token] = SecureRandom.base64(32)",
          "user.api_key = SecureRandom.hex(24)",
          "reset_token = SecureRandom.urlsafe_base64(48)"
        ],
        ruby_specific: %{
          mersenne_twister_facts: [
            "Period: 2^19937-1 (statistically excellent but cryptographically useless)",
            "State size: 624 words (can be recovered from outputs)",
            "Seed vulnerability: Same seed = same sequence forever",
            "Version consistency: Same sequence across Ruby versions",
            "Predictability: Given n outputs, can predict all future outputs"
          ],
          secure_libraries: [
            "SecureRandom: Ruby standard library for cryptographic randomness",
            "OpenSSL::Random: Lower-level cryptographic random access",
            "BCrypt: Secure password hashing with built-in salting",
            "/dev/urandom: OS-level entropy source (SecureRandom backend)"
          ],
          migration_patterns: [
            "rand(n) → SecureRandom.random_number(n) # For numeric values",
            "rand.to_s(36) → SecureRandom.alphanumeric(n) # For alphanumeric",
            "(0...n).map{rand(65..90).chr}.join → SecureRandom.hex(n/2)",
            "srand(seed); rand(n) → SecureRandom.random_number(n) # Remove seeding"
          ]
        }
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between cryptographically dangerous rand()
  usage and acceptable non-security uses.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.WeakRandom.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.WeakRandom.ast_enhancement()
      iex> enhancement.min_confidence
      0.6
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        method_names: ["rand", "srand", "random_number"],
        receiver_analysis: %{
          check_random_context: true,
          classes: ["Random", "Kernel"],
          modules: ["Math", "Kernel"]
        },
        usage_analysis: %{
          check_security_context: true,
          detect_token_generation: true,
          check_variable_assignment: true,
          security_indicators: ["token", "key", "session", "api", "auth", "password", "reset", "csrf"]
        }
      },
      context_rules: %{
        exclude_paths: [
          ~r/test/,
          ~r/spec/,
          ~r/fixtures/,
          ~r/examples/,
          ~r/benchmark/,
          ~r/games?/,
          ~r/simulation/
        ],
        check_cryptographic_context: true,
        safe_libraries: [
          "SecureRandom", "OpenSSL::Random", "BCrypt",
          "Digest::SHA", "OpenSSL::Digest"
        ],
        dangerous_contexts: [
          "session_token", "api_key", "auth_token", "csrf_token",
          "password_reset", "verification_code", "access_token",
          "refresh_token", "nonce", "salt", "iv"
        ],
        security_variable_patterns: [
          ~r/token/i, ~r/key/i, ~r/session/i, ~r/auth/i,
          ~r/password/i, ~r/secret/i, ~r/csrf/i, ~r/nonce/i
        ],
        acceptable_uses: %{
          games_simulation: true,
          testing_fixtures: true,
          mathematical_operations: true,
          non_security_randomization: true
        }
      },
      confidence_rules: %{
        base: 0.4,
        adjustments: %{
          "security_variable_name" => 0.4,
          "in_auth_method" => 0.3,
          "in_session_method" => 0.3,
          "token_generation_pattern" => 0.3,
          "string_conversion_chaining" => 0.2,
          "large_number_range" => 0.2,
          "uses_securerandom" => -0.9,
          "in_test_file" => -0.6,
          "in_game_context" => -0.5,
          "mathematical_operation" => -0.4,
          "small_range_non_security" => -0.3,
          "commented_code" => -1.0
        }
      },
      min_confidence: 0.6
    }
  end
end