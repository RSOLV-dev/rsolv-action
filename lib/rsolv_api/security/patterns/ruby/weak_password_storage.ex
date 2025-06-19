defmodule RsolvApi.Security.Patterns.Ruby.WeakPasswordStorage do
  @moduledoc """
  Pattern for detecting weak password storage vulnerabilities in Ruby applications.
  
  This pattern identifies when passwords are stored using weak or insecure hashing
  algorithms, or stored in plaintext, which can lead to account compromise when
  databases are breached.
  
  ## Vulnerability Details
  
  Weak password storage occurs when applications use cryptographically weak hashing
  algorithms (MD5, SHA1), store passwords in plaintext, or use inadequate security
  measures for protecting user credentials. This makes passwords vulnerable to
  brute force attacks and rainbow table lookups when databases are compromised.
  
  ### Attack Example
  ```ruby
  # Vulnerable password storage implementations
  class UserController < ApplicationController
    def create_user
      # VULNERABLE: MD5 password hashing
      user.password = Digest::MD5.hexdigest(params[:password])
      
      # VULNERABLE: SHA1 password hashing with salt
      user.encrypted_password = Digest::SHA1.hexdigest(params[:password] + salt)
      
      # VULNERABLE: SHA256 without proper salt
      user.password_digest = Digest::SHA256.hexdigest(params[:password])
      
      # VULNERABLE: Plaintext password storage
      user.password = params[:password]
      
      # VULNERABLE: Simple string operations
      user.encrypted_password = Base64.encode64(params[:password])
      
      user.save!
    end
  end
  
  # Attack scenarios:
  # - Rainbow table lookups for MD5/SHA1 hashes
  # - Brute force attacks on weak hashing algorithms
  # - Dictionary attacks on unsalted hashes
  # - Direct credential theft from plaintext storage
  ```
  
  **Real-world Impact:**
  CVE-2024-47529 demonstrated clear text password storage leading to massive
  credential theft. Many applications store passwords using MD5 or SHA1,
  making them vulnerable to rainbow table attacks and brute force.
  
  **Safe Alternative:**
  ```ruby
  # SECURE: Use bcrypt for password hashing
  class SecureUserController < ApplicationController
    def create_user
      # SECURE: bcrypt with automatic salt generation
      user.password = BCrypt::Password.create(params[:password])
      
      # SECURE: Rails has_secure_password (uses bcrypt internally)
      user.password = params[:password]  # with has_secure_password in model
      
      # SECURE: Argon2 for even stronger security
      user.password_digest = Argon2::Password.create(params[:password])
      
      # SECURE: scrypt with proper configuration
      user.encrypted_password = SCrypt::Password.create(
        params[:password], 
        cost: 16384, 
        block_size: 8, 
        parallelization: 1
      )
      
      user.save!
    end
  end
  
  # Model with secure password handling
  class User < ApplicationRecord
    has_secure_password  # Automatically uses bcrypt
    
    validates :password, 
      presence: true, 
      length: { minimum: 8 },
      format: { with: /\A(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/ }
  end
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "ruby-weak-password-storage",
      name: "Weak Password Storage",
      description: "Detects insecure password storage methods including weak hashing algorithms and plaintext storage",
      type: :cryptographic_failure,
      severity: :critical,
      languages: ["ruby"],
      regex: [
        # MD5 password hashing patterns - assignment and hash calculation
        ~r/(?:password|encrypted_password|password_digest|password_hash)\s*=\s*Digest::MD5\.(hexdigest|digest)/,
        ~r/(?:password|encrypted_password|password_digest|password_hash)\s*=\s*MD5\.(hexdigest|digest)/,
        ~r/hash\s*=\s*Digest::MD5\.(new\.)?(hexdigest|digest)\s*\(\s*(?:user_password|password)/,
        ~r/Digest::MD5\.(hexdigest|digest)\s*\(\s*(?:params\[.*?password|password|plain_password)/,
        
        # SHA1 password hashing patterns - assignment and hash calculation  
        ~r/(?:password|encrypted_password|password_digest|password_hash)\s*=\s*Digest::SHA1\.(hexdigest|digest)/,
        ~r/(?:password|encrypted_password|password_digest|password_hash)\s*=\s*SHA1\.(hexdigest|digest)/,
        ~r/hash\s*=\s*Digest::SHA1\.(new\.)?(hexdigest|digest)\s*\(\s*(?:user_password|password)/,
        ~r/Digest::SHA1\.(hexdigest|digest)\s*\(\s*(?:params\[.*?password|password|plain_password)/,
        
        # SHA256 without proper implementation (vulnerable when used alone)
        ~r/(?:password|encrypted_password|password_digest|password_hash)\s*=\s*Digest::SHA256\.(hexdigest|digest)/,
        ~r/(?:password|encrypted_password|password_digest|password_hash)\s*=\s*SHA256\.(hexdigest|digest)/,
        ~r/hash\s*=\s*SHA256\.(hexdigest|digest)\s*\(\s*(?:user_password|password)/,
        ~r/Digest::SHA256\.(hexdigest|digest)\s*\(\s*(?:params\[.*?password|password|plain_password)/,
        
        # Plaintext password assignment patterns
        ~r/(?:password|encrypted_password|password_digest)\s*=\s*params\[:password\]/,
        ~r/(?:password|encrypted_password|password_digest)\s*=\s*plain_password/,
        ~r/(?:password|encrypted_password|password_digest)\s*=\s*user_input/,
        ~r/(?:password|encrypted_password|password_digest)\s*=\s*password(?!\w)/,  # Direct assignment like "user.password_digest = password"
        ~r/password_field\s*=\s*(?:params|user_input|plain_password)/,
        
        # Simple/weak encoding patterns  
        ~r/(?:password|encrypted_password|password_digest|encrypted)\s*=\s*Base64\.encode64\s*\(\s*password/,
        ~r/(?:password|encrypted_password|password_digest)\s*=.*?\.crypt\s*\(/,
        ~r/(?:password|encrypted_password|password_digest)\s*=.*?\.to_s\s*\+\s*["']salt["']/,
        ~r/hash\s*=\s*password\.to_s\s*\+\s*["']salt["']/,  # String concatenation hashing
        ~r/(?:password|encrypted_password|password_digest)\s*=\s*password\.crypt\s*\(/
      ],
      cwe_id: "CWE-256",
      owasp_category: "A02:2021",
      recommendation: "Use bcrypt, argon2, or scrypt for password hashing. Rails provides has_secure_password for secure password handling.",
      test_cases: %{
        vulnerable: [
          ~S|user.password = Digest::MD5.hexdigest(params[:password])|,
          ~S|password_hash = Digest::SHA1.digest(password)|,
          ~S|user.encrypted_password = Digest::SHA256.hexdigest(plain_password)|,
          ~S|user.password = params[:password]|,
          ~S|password_digest = Base64.encode64(password)|
        ],
        safe: [
          ~S|user.password = BCrypt::Password.create(params[:password])|,
          ~S|has_secure_password # Rails built-in|,
          ~S|user.password_digest = Argon2::Password.create(password)|,
          ~S|password_hash = SCrypt::Password.create(password)|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Weak password storage is a critical cryptographic failure that occurs when
      applications store user passwords using inadequate security measures. This
      includes using cryptographically weak hashing algorithms (MD5, SHA1), storing
      passwords in plaintext, or using unsalted hashes that are vulnerable to
      rainbow table attacks.
      
      **How Weak Password Storage Works:**
      Passwords are one of the most sensitive pieces of user data, yet many applications
      store them insecurely:
      - **Plaintext Storage**: Passwords stored without any protection
      - **Weak Hashing**: Using MD5, SHA1, or SHA256 without proper salting
      - **Unsalted Hashes**: Hashes without unique salts for each password
      - **Fast Hashing**: Using algorithms not designed for password security
      
      **Ruby-Specific Vulnerabilities:**
      Ruby applications commonly make these password storage mistakes:
      - Using Digest::MD5 or Digest::SHA1 from the standard library
      - Simple Base64 encoding thinking it provides security
      - Direct assignment of plaintext passwords to database fields
      - Using crypt() function without understanding its limitations
      - SHA256 without proper salting and key stretching
      
      **Critical Security Impact:**
      Weak password storage enables various attack vectors:
      - **Rainbow Table Attacks**: Pre-computed hash lookups for common passwords
      - **Brute Force Attacks**: Fast algorithms allow rapid password cracking
      - **Dictionary Attacks**: Testing common passwords against weak hashes
      - **Credential Reuse**: Compromised passwords used across other services
      - **Account Takeover**: Direct access to user accounts with compromised credentials
      
      **Rails-Specific Considerations:**
      Rails provides built-in secure password handling, but developers often bypass it:
      - has_secure_password automatically uses bcrypt with proper salting
      - Many developers implement custom password handling incorrectly
      - Legacy Rails applications may use outdated password storage methods
      - Migration from older systems may retain weak password storage
      
      **Common Attack Scenarios:**
      - Database breaches exposing weak password hashes
      - Insider threats with database access
      - SQL injection leading to password hash extraction
      - Backup file exposure containing password data
      - Log file analysis revealing password storage methods
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-256",
          title: "Unprotected Storage of Credentials",
          url: "https://cwe.mitre.org/data/definitions/256.html"
        },
        %{
          type: :cwe,
          id: "CWE-257",
          title: "Storing Passwords in a Recoverable Format",
          url: "https://cwe.mitre.org/data/definitions/257.html"
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
          id: "owasp_password_storage",
          title: "OWASP Password Storage Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"
        },
        %{
          type: :research,
          id: "rails_security_guide",
          title: "Ruby on Rails Security Guide - User Management",
          url: "https://guides.rubyonrails.org/security.html#user-management"
        },
        %{
          type: :research,
          id: "nist_password_guidelines",
          title: "NIST Special Publication 800-63B - Authentication Guidelines",
          url: "https://pages.nist.gov/800-63-3/sp800-63b.html"
        }
      ],
      attack_vectors: [
        "Rainbow table attacks against MD5/SHA1 password hashes",
        "Brute force attacks on weak hashing algorithms with fast computation",
        "Dictionary attacks using common password lists against unsalted hashes",
        "Database breach leading to plaintext password exposure",
        "Credential stuffing using passwords from previous breaches",
        "Social engineering using recovered plaintext passwords",
        "Account takeover through direct password access",
        "Privilege escalation using compromised administrative passwords",
        "Lateral movement using shared passwords across systems",
        "Identity theft using personal information and passwords"
      ],
      real_world_impact: [
        "CVE-2024-47529: Clear text password storage in production systems leading to credential theft",
        "CVE-2019-8331: Ruby on Rails password reset vulnerability exposing weak password storage",
        "LinkedIn data breach (2012): 6.5 million SHA1 password hashes cracked within hours",
        "Adobe data breach (2013): 150 million encrypted passwords compromised due to weak encryption",
        "Ashley Madison breach (2015): MD5 and bcrypt passwords, MD5 hashes quickly cracked",
        "Yahoo breaches (2013-2014): Over 1 billion accounts with MD5 password hashes compromised",
        "Dropbox breach (2012): 68 million bcrypt and SHA1 password hashes stolen",
        "MySpace breach (2013): 360 million SHA1 password hashes, many cracked within days",
        "Major Rails applications compromised due to custom weak password storage implementations",
        "E-commerce platforms losing customer trust after password storage vulnerabilities"
      ],
      cve_examples: [
        %{
          id: "CVE-2024-47529",
          description: "Clear text password storage vulnerability in production systems",
          severity: "critical",
          cvss: 9.1,
          note: "Application stored user passwords in clear text format in database"
        },
        %{
          id: "CVE-2019-8331",
          description: "Ruby on Rails password reset vulnerability",
          severity: "high",
          cvss: 7.5,
          note: "Weak password storage combined with reset token vulnerabilities"
        },
        %{
          id: "CVE-2021-22885",
          description: "Ruby on Rails information disclosure in password fields",
          severity: "medium",
          cvss: 5.3,
          note: "Password information disclosure through error messages and logging"
        },
        %{
          id: "CVE-2020-8164",
          description: "Ruby on Rails password confirmation bypass",
          severity: "high",
          cvss: 7.5,
          note: "Weak password validation allowing insecure password storage"
        }
      ],
      detection_notes: """
      This pattern detects weak password storage vulnerabilities by identifying
      insecure password handling methods in Ruby code:
      
      **Primary Detection Points:**
      - MD5/SHA1/SHA256 usage for password hashing
      - Plaintext password assignment to database fields
      - Base64 encoding used for password "encryption"
      - Simple string operations on password data
      - Direct assignment of user input to password fields
      
      **Ruby-Specific Patterns:**
      - Digest::MD5, Digest::SHA1, Digest::SHA256 usage with passwords
      - Direct assignment patterns: password = params[:password]
      - Common password field names: password, encrypted_password, password_digest
      - Simple encoding methods: Base64.encode64, crypt(), to_s operations
      - User input sources: params[:password], plain_password, user_input
      
      **False Positive Considerations:**
      - Secure password libraries (BCrypt, Argon2, SCrypt) usage
      - Rails has_secure_password implementation
      - Test code and fixtures with dummy passwords
      - Non-password fields using similar naming patterns
      - Commented out insecure implementations
      
      **Detection Enhancements:**
      The AST enhancement provides sophisticated analysis:
      - Password field identification and context analysis
      - Hashing algorithm strength assessment
      - User input flow tracking from params to storage
      - Secure password library usage detection
      """,
      safe_alternatives: [
        "Use bcrypt for password hashing: BCrypt::Password.create(password)",
        "Use Rails has_secure_password in your User model for automatic bcrypt",
        "Use Argon2 for maximum security: Argon2::Password.create(password)",
        "Use scrypt with proper parameters: SCrypt::Password.create(password)",
        "Implement proper password validation rules (length, complexity)",
        "Use strong, unique salts for each password (automatic with bcrypt/argon2)",
        "Implement rate limiting for password-related operations",
        "Use environment variables for any password-related configuration",
        "Implement secure password reset mechanisms with time-limited tokens",
        "Regular security audits of password storage implementation"
      ],
      additional_context: %{
        common_mistakes: [
          "Using MD5 or SHA1 thinking they provide adequate security",
          "Implementing custom password hashing instead of using proven libraries",
          "Storing passwords in plaintext 'temporarily' during development",
          "Using Base64 encoding thinking it's encryption",
          "Not using unique salts for each password hash",
          "Using fast hashing algorithms not designed for password security",
          "Storing password hints or security questions insecurely",
          "Not validating password strength before hashing"
        ],
        secure_patterns: [
          "has_secure_password # Rails built-in secure password handling",
          "BCrypt::Password.create(password) # Industry standard password hashing",
          "Argon2::Password.create(password) # Latest recommended algorithm",
          "SCrypt::Password.create(password, cost: 16384) # Strong alternative",
          "validates :password, length: { minimum: 8 } # Strong password validation",
          "password_digest # Rails convention for hashed passwords",
          "SecureRandom.hex(32) # Secure random salt generation"
        ],
        ruby_specific: %{
          secure_libraries: [
            "bcrypt: Industry standard, used by Rails has_secure_password",
            "argon2: Winner of password hashing competition, most secure",
            "scrypt: Strong alternative, good for memory-hard functions",
            "pbkdf2: Acceptable but slower than bcrypt for same security",
            "Rails has_secure_password: Automatic bcrypt with validation"
          ],
          rails_integration: [
            "has_secure_password automatically handles bcrypt hashing",
            "password_digest field stores the bcrypt hash",
            "authenticate method for password verification",
            "password_confirmation for user input validation",
            "Strong parameters to control password input",
            "validates_confirmation_of for password confirmation"
          ],
          migration_strategies: [
            "Gradual migration from weak to strong hashing on user login",
            "Force password reset for users with weak hashes",
            "Dual storage during transition period for compatibility",
            "Audit logging for password storage changes",
            "User notification about security improvements"
          ]
        }
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual weak password storage
  and acceptable password handling patterns.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.WeakPasswordStorage.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.WeakPasswordStorage.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "AssignmentExpression",
        password_field_analysis: %{
          check_password_fields: true,
          password_field_names: ["password", "encrypted_password", "password_digest", "password_hash", "password_field"],
          require_password_context: true
        },
        weak_hashing_analysis: %{
          check_hashing_methods: true,
          weak_algorithms: ["MD5", "SHA1", "SHA256"],
          secure_algorithms: ["BCrypt", "Argon2", "SCrypt", "PBKDF2"],
          detect_algorithm_usage: true
        },
        user_input_analysis: %{
          check_user_input_sources: true,
          input_sources: ["params", "user_input", "plain_password", "request"],
          check_direct_assignment: true,
          validate_input_flow: true
        },
        encoding_analysis: %{
          check_weak_encoding: true,
          weak_encoding_methods: ["Base64.encode64", "crypt", "to_s"],
          detect_plaintext_patterns: true
        }
      },
      context_rules: %{
        exclude_paths: [
          ~r/test/,
          ~r/spec/,
          ~r/fixtures/,
          ~r/factories/,
          ~r/seeds/,
          ~r/examples/,
          ~r/demo/
        ],
        check_secure_libraries: %{
          bcrypt_usage: ~r/BCrypt::/,
          argon2_usage: ~r/Argon2::/,
          scrypt_usage: ~r/SCrypt::/,
          has_secure_password: ~r/has_secure_password/,
          rails_conventions: ~r/password_digest/
        },
        safe_patterns: %{
          secure_password_creation: true,
          rails_secure_password: true,
          proper_validation: true,
          environment_checks: true
        },
        dangerous_contexts: [
          "password assignment",
          "user registration",
          "password update",
          "credential storage",
          "authentication setup"
        ]
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "weak_algorithm_usage" => 0.3,
          "plaintext_assignment" => 0.4,
          "user_input_direct_assignment" => 0.3,
          "password_field_context" => 0.2,
          "weak_encoding_usage" => 0.2,
          "controller_context" => 0.1,
          "bcrypt_usage_present" => -0.4,
          "has_secure_password_present" => -0.5,
          "argon2_usage_present" => -0.4,
          "secure_library_usage" => -0.3,
          "test_context" => -0.3,
          "commented_out" => -1.0
        }
      },
      min_confidence: 0.7
    }
  end
end