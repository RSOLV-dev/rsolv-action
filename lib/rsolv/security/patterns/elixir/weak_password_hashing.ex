defmodule Rsolv.Security.Patterns.Elixir.WeakPasswordHashing do
  @moduledoc """
  Weak Password Hashing vulnerability pattern for Elixir applications.

  This pattern detects password hashing implementations using fast cryptographic 
  hash functions (MD5, SHA1, SHA256, SHA512) instead of proper password hashing 
  algorithms designed to be computationally expensive.

  ## Vulnerability Details

  Weak password hashing occurs when applications use general-purpose hash functions 
  for password storage:
  - Using :crypto.hash with MD5, SHA1, SHA256, SHA512
  - Simple salting without key stretching
  - Fast hashing algorithms vulnerable to brute force
  - Insufficient computational cost for password protection

  ## Technical Impact

  Security risks through weak password hashing:
  - Brute force attacks using GPUs or specialized hardware
  - Rainbow table attacks on unsalted or weakly salted hashes
  - Credential stuffing from compromised password databases
  - Rapid password recovery even with salted hashes

  ## Examples

  Vulnerable patterns:
  ```elixir
  # VULNERABLE - SHA256 is too fast for passwords
  :crypto.hash(:sha256, password <> salt)
  
  # VULNERABLE - MD5 is broken for passwords
  :crypto.hash(:md5, password)
  
  # VULNERABLE - SHA512 still too fast
  Base.encode16(:crypto.hash(:sha512, password))
  
  # VULNERABLE - Simple salting insufficient
  password_hash = :crypto.hash(:sha256, password <> get_salt())
  ```

  Safe alternatives:
  ```elixir
  # SAFE - Argon2 (recommended)
  Argon2.hash_pwd_salt(password)
  
  # SAFE - Bcrypt with cost factor
  Bcrypt.hash_pwd_salt(password, log_rounds: 12)
  
  # SAFE - Pbkdf2 with iterations
  Pbkdf2.hash_pwd_salt(password, rounds: 100_000)
  
  # SAFE - Verification
  Argon2.verify_pass(password, stored_hash)
  ```

  ## Attack Scenarios

  1. **Database Breach**: Attacker obtains password hashes and uses GPU clusters 
     to crack SHA256 hashes at billions of attempts per second

  2. **Rainbow Tables**: Pre-computed hash tables used to instantly reverse 
     common passwords hashed with MD5 or SHA1

  3. **Targeted Attack**: Attacker focuses computational resources on high-value 
     accounts using weak hashing algorithms

  ## References

  - CWE-916: Use of Password Hash With Insufficient Computational Effort
  - OWASP Top 10 2021 - A02: Cryptographic Failures
  - NIST SP 800-63B: Digital Identity Guidelines
  - Password Hashing Competition (PHC) Winner: Argon2
  """

  use Rsolv.Security.Patterns.PatternBase

  @impl true
  def pattern do
    %Rsolv.Security.Pattern{
      id: "elixir-weak-password-hashing",
      name: "Weak Password Hashing",
      description: "Fast hash functions like SHA256 are insufficient for password storage",
      type: :weak_crypto,
      severity: :high,
      languages: ["elixir"],
      frameworks: [],
      regex: [
        # :crypto.hash with password - exclude comments and @doc
        ~r/^(?!\s*#)(?!\s*@doc).*:crypto\.hash\s*\(\s*:(?:sha|sha256|sha512|sha224|md5)\s*,\s*.*password/m,
        
        # Base.encode with crypto.hash and password - exclude comments and @doc
        ~r/^(?!\s*#)(?!\s*@doc).*Base\.(?:encode16|encode64|encode32|url_encode64|hex_encode32|hex_encode16)\s*\(\s*:crypto\.hash\s*\(.*pass/m,
        
        # Password hash assignment - exclude comments and @doc
        ~r/^(?!\s*#)(?!\s*@doc).*(?:password_hash|pwd_hash|hashed_password|pass_hash|user_password_hash)\s*=\s*:crypto\.hash/m,
        
        # Legacy crypto functions with password - exclude comments and @doc
        ~r/^(?!\s*#)(?!\s*@doc).*:crypto\.(?:sha|sha256|sha512|md5)\s*\(\s*.*password/m,
        
        # :erlang.md5 with password - exclude comments and @doc
        ~r/^(?!\s*#)(?!\s*@doc).*:erlang\.md5\s*\(\s*.*password/m,
        
        # Pipeline with crypto.hash and password - exclude comments and @doc
        ~r/^(?!\s*#)(?!\s*@doc).*password.*\|>.*:crypto\.hash/m,
        
        # Assignment with pipeline to crypto.hash - exclude comments and @doc
        ~r/^(?!\s*#)(?!\s*@doc).*=.*\n.*\|>.*:crypto\.hash/m,
        
        # then(&:crypto.hash) pattern - exclude comments and @doc
        ~r/^(?!\s*#)(?!\s*@doc).*then\s*\(&:crypto\.hash/m
      ],
      cwe_id: "CWE-916",
      owasp_category: "A02:2021",
      recommendation: "Use Argon2, Bcrypt, or Pbkdf2 for password hashing",
      test_cases: %{
        vulnerable: [
          ~S|:crypto.hash(:sha256, password <> salt)|,
          ~S|:crypto.hash(:md5, password)|,
          ~S|password_hash = :crypto.hash(:sha512, user_password)|,
          ~S|Base.encode16(:crypto.hash(:sha256, password))|
        ],
        safe: [
          ~S|Argon2.hash_pwd_salt(password)|,
          ~S|Bcrypt.hash_pwd_salt(password, log_rounds: 12)|,
          ~S|Pbkdf2.hash_pwd_salt(password)|,
          ~S|Argon2.verify_pass(password, hash)|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      attack_vectors: """
      1. brute force attacks using GPU clusters to crack billions of SHA256 hashes per second
      2. Rainbow table attacks with pre-computed hashes for common passwords and variations
      3. Dictionary attacks enhanced by fast hash computation allowing rapid password testing
      4. Hybrid attacks combining dictionary words with common modifications and patterns
      5. Distributed cracking using botnets or cloud resources to parallelize hash cracking
      """,
      business_impact: """
      High: Weak password hashing can result in:
      - Mass credential compromise exposing all user accounts after database breach
      - Account takeover attacks leading to financial losses and fraud
      - Regulatory fines for inadequate password protection (GDPR, PCI DSS)
      - Reputation damage from publicized password breaches
      - Legal liability from negligent security practices affecting users
      """,
      technical_impact: """
      High: Insufficient password hashing enables:
      - Rapid password recovery using modern GPU hardware (billions/second for SHA256)
      - rainbow table attacks instantly reversing common password hashes
      - Credential stuffing attacks after password database compromise
      - Lateral movement using cracked credentials across systems
      - Long-term persistent access through compromised accounts
      """,
      likelihood: "High: Common mistake as developers often use familiar hash functions without understanding password-specific requirements",
      cve_examples: [
        "CWE-916: Use of Password Hash With Insufficient Computational Effort",
        "CVE-2012-3287: Insufficient computational effort in password hashing",
        "CVE-2020-5398: Spring Security weak password encoding",
        "LinkedIn 2012: 117 million SHA1 password hashes cracked"
      ],
      compliance_standards: [
        "OWASP Top 10 2021 - A02: Cryptographic Failures",
        "NIST SP 800-63B: Memorized Secret Verifiers (Section 5.1.1.2)",
        "PCI DSS v4.0 - Requirement 8.3.2: Strong cryptography for passwords",
        "ISO 27001 - A.9.4.3: Password management system"
      ],
      remediation_steps: """
      1. Replace all :crypto.hash password hashing with Argon2
      2. Implement password hashing library (argon2_elixir recommended)
      3. Migrate existing password hashes during user login
      4. Configure appropriate cost factors (Argon2: 3 iterations, 12MB memory)
      5. Use constant-time comparison for password verification
      6. Implement secure password reset for hash migration
      """,
      prevention_tips: """
      1. Always use dedicated password hashing libraries (Argon2, Bcrypt, Pbkdf2)
      2. Never use general-purpose hash functions (MD5, SHA family) for passwords
      3. Configure computational cost factors appropriately for your security requirements
      4. Keep hashing libraries updated to latest versions
      5. Use built-in verification functions to prevent timing attacks
      6. Consider using Argon2id variant for best security
      """,
      detection_methods: """
      1. Static analysis for :crypto.hash usage with password variables
      2. Code review focusing on authentication and user management
      3. Dependency scanning for password hashing libraries
      4. Security testing attempting to crack sample password hashes
      5. Configuration review for hashing algorithm parameters
      """,
      safe_alternatives: """
      1. Argon2: Argon2.hash_pwd_salt(password) # Memory-hard, recommended
      2. Bcrypt: Bcrypt.hash_pwd_salt(password, log_rounds: 12) # CPU-hard
      3. Pbkdf2: Pbkdf2.hash_pwd_salt(password, rounds: 100_000) # Iteration-based
      4. Verification: Argon2.verify_pass(password, hash) # Constant-time
      5. Migration: Comeonin library provides unified interface
      6. Configuration: Use environment-specific cost factors
      """
    }
  end

  @impl true  
  def ast_enhancement do
    %{
      min_confidence: 0.8,
      context_rules: %{
        weak_algorithms: [
          "md5", "sha", "sha1", "sha224", "sha256", "sha384", "sha512"
        ],
        strong_algorithms: [
          "argon2", "bcrypt", "pbkdf2", "scrypt"
        ],
        password_indicators: [
          "password", "pwd", "pass", "passwd", "passphrase",
          "secret", "pin", "passcode"
        ],
        hash_functions: [
          ":crypto.hash", ":crypto.sha", ":crypto.sha256", 
          ":crypto.md5", ":erlang.md5"
        ]
      },
      confidence_rules: %{
        base: 0.8,
        adjustments: %{
          weak_algorithm_bonus: 0.2,
          password_indicator_bonus: 0.15,
          strong_algorithm_penalty: -0.9,
          salt_presence_penalty: -0.1,
          test_context_penalty: -0.7,
          migration_context_penalty: -0.5
        }
      },
      ast_rules: %{
        node_type: "password_hashing_analysis",
        password_analysis: %{
          check_variable_names: true,
          password_patterns: ["password", "pwd", "pass"],
          check_function_context: true,
          auth_functions: ["authenticate", "login", "register", "hash_password"]
        },
        algorithm_analysis: %{
          check_crypto_functions: true,
          weak_hash_functions: [":crypto.hash", ":crypto.sha256", ":crypto.md5"],
          check_library_usage: true,
          strong_libraries: ["Argon2", "Bcrypt", "Pbkdf2"]
        },
        context_analysis: %{
          check_migration_context: true,
          migration_indicators: ["migrate", "upgrade", "legacy"],
          check_test_context: true,
          test_indicators: ["test", "spec", "example"]
        }
      }
    }
  end
end
