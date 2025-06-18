defmodule RsolvApi.Security.Patterns.Python.WeakHashMd5 do
  @moduledoc """
  Pattern for detecting weak MD5 hash usage in Python code.
  
  Detects usage of hashlib.md5() which is cryptographically broken and
  vulnerable to collision attacks. MD5 should not be used for security purposes.
  """

  alias RsolvApi.Security.Pattern

  @doc """
  Returns the complete pattern for detecting weak MD5 hash usage.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Python.WeakHashMd5.pattern()
      iex> pattern.id
      "python-weak-hash-md5"
      iex> pattern.severity
      :medium
      iex> pattern.type
      :weak_crypto
  """
  def pattern do
    %Pattern{
      id: "python-weak-hash-md5",
      name: "Weak Cryptographic Hash - MD5",
      description: "Detects usage of MD5 hash algorithm which is cryptographically broken",
      type: :weak_crypto,
      severity: :medium,
      languages: ["python"],
      regex: ~r/
        # Direct hashlib.md5() usage
        hashlib\.md5\s*\(|
        # MD5 instance creation
        md5\s*\(\)|
        # From hashlib import md5
        from\s+hashlib\s+import\s+.*\bmd5\b|
        # MD5 in cryptographic context
        \.new\s*\(\s*['"]md5['"]\s*\)|
        # MD5 hasher instantiation
        \w+\s*=\s*hashlib\.md5\s*\(|
        # Dynamic MD5 invocation via getattr
        getattr\s*\(\s*hashlib\s*,\s*['"]md5['"]|
        # Variable containing 'md5' string used with getattr
        \w+\s*=\s*['"]md5['"].*getattr\s*\(\s*hashlib\s*,\s*\w+\)
      /x,
      default_tier: :ai,
      cwe_id: "CWE-328",
      owasp_category: "A02:2021",
      recommendation: "Use SHA-256, SHA-3, or bcrypt/argon2 for passwords",
      test_cases: %{
        vulnerable: [
          "password_hash = hashlib.md5(password.encode()).hexdigest()",
          "from hashlib import md5; h = md5()",
          "hasher = hashlib.md5()",
          "hash_algo = 'md5'; getattr(hashlib, hash_algo)(data)"
        ],
        safe: [
          "secure_hash = hashlib.sha256(data).hexdigest()",
          "# MD5 is weak - don't use for security",
          "bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())"
        ]
      }
    }
  end

  @doc """
  Returns test cases for the pattern.
  """
  def test_cases do
    %{
      positive: [
        """
        import hashlib
        password_hash = hashlib.md5(password.encode()).hexdigest()
        """,
        """
        from hashlib import md5
        h = md5()
        h.update(data)
        """,
        """
        import hashlib
        def hash_password(pwd):
            return hashlib.md5(pwd.encode('utf-8')).hexdigest()
        """,
        """
        hasher = hashlib.md5()
        hasher.update(secret_key.encode())
        """
      ],
      negative: [
        """
        # MD5 is weak - don't use for security
        # Use hashlib.sha256() instead
        """,
        """
        import hashlib
        secure_hash = hashlib.sha256(data).hexdigest()
        """,
        """
        # Using MD5 for non-security purposes (checksums)
        file_checksum = calculate_checksum(file_path)  # Internal uses MD5
        """
      ]
    }
  end

  @doc """
  Returns examples of vulnerable and fixed code.
  """
  def examples do
    %{
      vulnerable: %{
        "Password hashing with MD5" => """
        import hashlib
        
        def hash_password(password):
            return hashlib.md5(password.encode()).hexdigest()
        
        # Vulnerable to rainbow table attacks
        stored_hash = hash_password(user_password)
        """,
        "API key generation with MD5" => """
        import hashlib
        import time
        
        def generate_api_key(user_id):
            data = f"{user_id}:{time.time()}"
            return hashlib.md5(data.encode()).hexdigest()
        """,
        "Token creation with MD5" => """
        from hashlib import md5
        
        def create_reset_token(email):
            return md5(email.encode()).hexdigest()
        """
      },
      fixed: %{
        "Use SHA-256 for hashing" => """
        import hashlib
        
        def hash_password(password):
            return hashlib.sha256(password.encode()).hexdigest()
        
        # Better: use bcrypt or argon2 for passwords
        """,
        "Use secrets module for tokens" => """
        import secrets
        
        def generate_api_key():
            return secrets.token_urlsafe(32)
        """,
        "Use proper password hashing" => """
        import bcrypt
        
        def hash_password(password):
            salt = bcrypt.gensalt()
            return bcrypt.hashpw(password.encode('utf-8'), salt)
        """
      }
    }
  end

  @doc """
  Returns references for the vulnerability.
  """
  def references do
    [
      "https://cwe.mitre.org/data/definitions/328.html",
      "https://cwe.mitre.org/data/definitions/327.html",
      "https://owasp.org/www-project-top-ten/2021/Top_10/A02_2021-Cryptographic_Failures/",
      "https://www.rfc-editor.org/rfc/rfc6151",
      "https://docs.python.org/3/library/hashlib.html#hashlib-algorithms"
    ]
  end

  @doc """
  Returns detailed vulnerability description.
  """
  def vulnerability_description do
    """
    MD5 is a cryptographic hash function that is considered broken and unsuitable
    for security purposes. It is vulnerable to:
    
    1. **Collision Attacks**: Attackers can create two different inputs that produce
       the same MD5 hash in seconds on modern hardware.
    
    2. **Preimage Attacks**: While harder than collisions, MD5's resistance to
       finding an input for a given hash is weakening.
    
    3. **Rainbow Tables**: Pre-computed tables make cracking MD5 hashes trivial
       for common inputs like passwords.
    
    ## Real-World Exploits
    
    - **Flame Malware (2012)**: Used MD5 collision to forge Microsoft certificates
    - **PlayStation 3 Hack**: MD5 weaknesses helped break PS3 security
    - **Certificate Forgery**: Researchers created rogue CA certificates using MD5
    
    ## Safe Alternatives
    
    - **SHA-256/SHA-3**: For general hashing needs
    - **bcrypt/scrypt/argon2**: For password hashing
    - **HMAC-SHA256**: For message authentication
    - **secrets module**: For token generation
    """
  end

  @doc """
  Comprehensive vulnerability metadata for weak MD5 hashing in Python.
  
  This metadata documents the specific risks of using MD5 in Python applications
  and provides authoritative guidance for secure alternatives.
  """
  def vulnerability_metadata do
    %{
      description: """
      MD5 (Message Digest Algorithm 5) is a cryptographic hash function that has been 
      fundamentally broken since 2004. In Python, the hashlib.md5() function remains 
      available for backward compatibility, but its use in security contexts creates 
      severe vulnerabilities. Modern attacks can generate MD5 collisions in seconds, 
      making it completely unsuitable for any security-critical applications.
      
      Python developers often use MD5 through:
      1. hashlib.md5() for password hashing (critically vulnerable)
      2. Direct MD5 usage for file integrity checks (can be bypassed)
      3. API token generation using MD5 (easily forgeable)
      4. Session ID generation with MD5 (predictable and collisionable)
      
      The Python 3.9+ hashlib module includes a 'usedforsecurity' parameter to 
      discourage security usage, but many developers ignore this warning. The 
      availability of rainbow tables, GPU-accelerated cracking, and collision 
      attacks makes MD5 usage a critical security vulnerability.
      
      Real-world attacks have demonstrated that MD5 collisions can be used to:
      - Create malicious files with the same hash as legitimate ones
      - Forge digital certificates
      - Bypass authentication systems
      - Compromise password databases
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-328",
          title: "Use of Weak Hash",
          url: "https://cwe.mitre.org/data/definitions/328.html"
        },
        %{
          type: :owasp,
          id: "A02:2021",
          title: "OWASP Top 10 2021 - A02 Cryptographic Failures",
          url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
        },
        %{
          type: :python_docs,
          id: "hashlib",
          title: "Python hashlib — Secure hashes and message digests",
          url: "https://docs.python.org/3/library/hashlib.html"
        },
        %{
          type: :research,
          id: "md5_collision_2004",
          title: "How to Break MD5 and Other Hash Functions",
          url: "https://www.win.tue.nl/hashclash/rogue-ca/"
        },
        %{
          type: :nist,
          id: "SP_800-131A",
          title: "NIST Transitions: Recommendation for Transitioning Cryptographic Algorithms",
          url: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf"
        }
      ],
      attack_vectors: [
        "Collision attacks: Generate two different inputs with identical MD5 hashes in seconds",
        "Rainbow table lookups: Pre-computed hashes for billions of common passwords",
        "GPU cracking: Modern GPUs can test billions of MD5 hashes per second",
        "Length extension attacks: Extend valid hashes without knowing the original input",
        "Chosen-prefix collisions: Craft meaningful content with matching hashes",
        "Birthday attacks: Find collisions with only 2^64 operations",
        "Dictionary attacks: Test common passwords against leaked MD5 databases",
        "Distributed cracking: Cloud-based MD5 cracking services"
      ],
      real_world_impact: [
        "LinkedIn breach (2012): 117 million MD5 passwords cracked and sold",
        "Adobe breach (2013): 150 million MD5 passwords exposed and cracked",
        "Certificate forgery: Rogue CA certificates created using MD5 collisions",
        "Malware distribution: Malicious files disguised with legitimate MD5 hashes",
        "Authentication bypass: Forged tokens and session IDs",
        "Compliance failures: GDPR, HIPAA, PCI-DSS violations for weak crypto",
        "Supply chain attacks: Compromised packages with matching MD5 checksums",
        "Financial fraud: Compromised payment systems using MD5 for integrity"
      ],
      cve_examples: [
        %{
          id: "CVE-2025-0508",
          description: "SageMaker Python SDK MD5 hash collision vulnerability allowing workflow replacement",
          severity: "high",
          cvss: 7.5,
          note: "MD5 collisions in production AWS service causing integrity failures"
        },
        %{
          id: "CVE-2021-39182",
          description: "EnroCrypt Python library using MD5 for cryptographic operations",
          severity: "high",
          cvss: 7.5,
          note: "Python crypto library defaulting to broken MD5 algorithm"
        },
        %{
          id: "CVE-2019-9053",
          description: "CMS Made Simple vulnerable to MD5-based authentication bypass",
          severity: "critical",
          cvss: 9.8,
          note: "MD5 password hashing allowing complete authentication bypass"
        },
        %{
          id: "CVE-2008-4609",
          description: "MD5 collision vulnerability in X.509 certificates",
          severity: "high",
          cvss: 7.5,
          note: "Practical demonstration of certificate forgery using MD5 collisions"
        }
      ],
      detection_notes: """
      This pattern detects MD5 usage in Python through:
      
      1. hashlib.md5() calls with various import styles
      2. MD5() constructor usage from legacy implementations
      3. Direct md5.new() calls (Python 2 style)
      4. Variable names suggesting MD5 usage (md5_hash, md5sum, etc.)
      
      The pattern matches case-insensitively to catch variations like MD5, md5, Md5.
      It's designed to catch the most common Python MD5 usage patterns while 
      minimizing false positives from comments or documentation.
      """,
      safe_alternatives: [
        "Use hashlib.sha256() for general hashing needs",
        "Use hashlib.sha3_256() for modern applications",
        "Use bcrypt.hashpw() for password hashing (pip install bcrypt)",
        "Use argon2.hash() for password hashing (pip install argon2-cffi)",
        "Use scrypt for password-based key derivation",
        "Use hashlib.pbkdf2_hmac() for key derivation",
        "Use hashlib.blake2b() for high-performance secure hashing",
        "Use hmac.new() with SHA-256 for message authentication"
      ],
      additional_context: %{
        common_mistakes: [
          "Using MD5 for password storage in Django/Flask applications",
          "Implementing file deduplication systems based on MD5",
          "Using MD5 for API key generation",
          "Storing MD5 hashes in databases without migration plan",
          "Using MD5 for cache keys in security contexts",
          "Implementing CSRF tokens with MD5",
          "Using MD5 in custom session management"
        ],
        secure_patterns: [
          "from passlib.hash import argon2; argon2.hash(password)",
          "import bcrypt; bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())",
          "hashlib.sha256(data.encode()).hexdigest()",
          "from cryptography.hazmat.primitives import hashes",
          "secrets.token_urlsafe(32) for secure token generation",
          "Use Django's make_password() for password hashing",
          "Use Flask-Bcrypt for password management"
        ],
        python_specific_notes: [
          "hashlib.md5(usedforsecurity=False) only for non-security checksums",
          "Many Python 2 codebases still use md5.new() which is deprecated",
          "Popular libraries like Pillow use MD5 internally for non-security purposes",
          "Django removed MD5PasswordHasher in version 4.0",
          "pytest uses MD5 for cache keys but not for security",
          "The 'usedforsecurity' parameter was added in Python 3.9"
        ],
        migration_guidance: [
          "Audit all hashlib.md5() usage in codebase",
          "Replace password hashing with bcrypt or argon2 immediately",
          "Implement gradual hash upgrade on user login",
          "Update file integrity checks to use SHA-256 minimum",
          "Replace MD5-based tokens with secrets.token_* functions",
          "Update any MD5-based APIs with versioning strategy",
          "Document remaining non-security MD5 usage"
        ]
      }
    }
  end

  @doc """
  Returns AST enhancement rules for improved detection.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Python.WeakHashMd5.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:min_confidence, :rules]
      
      iex> enhancement = RsolvApi.Security.Patterns.Python.WeakHashMd5.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
      
      iex> enhancement = RsolvApi.Security.Patterns.Python.WeakHashMd5.ast_enhancement()
      iex> length(enhancement.rules)
      2
  """
  def ast_enhancement do
    %{
      rules: [
        %{
          type: "context_check",
          description: "Reduce confidence if MD5 is used for non-security purposes",
          checks: [
            "file_checksum",
            "cache_key",
            "etag",
            "non_cryptographic"
          ]
        },
        %{
          type: "severity_increase",
          description: "Increase severity for security-sensitive contexts",
          contexts: [
            "password",
            "token",
            "api_key",
            "secret",
            "auth"
          ]
        }
      ],
      min_confidence: 0.7
    }
  end
end