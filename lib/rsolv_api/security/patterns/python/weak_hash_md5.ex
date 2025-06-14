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
        \w+\s*=\s*hashlib\.md5\s*\(
      /x,
      default_tier: :public,
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