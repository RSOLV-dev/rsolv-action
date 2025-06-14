defmodule RsolvApi.Security.Patterns.Python.WeakHashSha1 do
  @moduledoc """
  Pattern for detecting weak SHA1 hash usage in Python code.
  
  Detects usage of hashlib.sha1() which is considered weak for security purposes
  due to known collision attacks. SHA1 should not be used for cryptographic security.
  """

  alias RsolvApi.Security.Pattern

  @doc """
  Returns the complete pattern for detecting weak SHA1 hash usage.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Python.WeakHashSha1.pattern()
      iex> pattern.id
      "python-weak-hash-sha1"
      iex> pattern.severity
      :medium
      iex> pattern.type
      :weak_crypto
  """
  def pattern do
    %Pattern{
      id: "python-weak-hash-sha1",
      name: "Weak Cryptographic Hash - SHA1",
      description: "Detects usage of SHA1 hash algorithm which is vulnerable to collision attacks",
      type: :weak_crypto,
      severity: :medium,
      languages: ["python"],
      regex: ~r/
        # Direct hashlib.sha1() usage
        hashlib\.sha1\s*\(|
        # SHA1 instance creation
        sha1\s*\(\)|
        # From hashlib import sha1
        from\s+hashlib\s+import\s+.*\bsha1\b|
        # SHA1 in cryptographic context
        \.new\s*\(\s*['"]sha1['"]\s*\)|
        # SHA1 hasher instantiation
        \w+\s*=\s*hashlib\.sha1\s*\(
      /x,
      default_tier: :public,
      cwe_id: "CWE-328",
      owasp_category: "A02:2021",
      recommendation: "Use SHA-256, SHA-3, or SHA-512 for secure hashing",
      test_cases: %{
        vulnerable: [
          "signature = hashlib.sha1(data.encode()).hexdigest()",
          "from hashlib import sha1; h = sha1()",
          "hasher = hashlib.sha1()",
          "hmac.new(key, message, hashlib.sha1)"
        ],
        safe: [
          "secure_hash = hashlib.sha256(data).hexdigest()",
          "strong_hash = hashlib.sha512(content).hexdigest()",
          "# SHA1 is weak - use SHA256 instead"
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
        signature = hashlib.sha1(data.encode()).hexdigest()
        """,
        """
        from hashlib import sha1
        h = sha1()
        h.update(message)
        """,
        """
        def create_signature(content):
            return hashlib.sha1(content).hexdigest()
        """,
        """
        hasher = hashlib.sha1()
        hasher.update(token.encode())
        """
      ],
      negative: [
        """
        # SHA1 is weak - use SHA256 instead
        secure_hash = hashlib.sha256(data).hexdigest()
        """,
        """
        import hashlib
        strong_hash = hashlib.sha512(content).hexdigest()
        """,
        """
        # SHA1 only for git compatibility
        git_hash = calculate_git_hash(content)  # Uses SHA1 internally
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
        "Digital signature with SHA1" => """
        import hashlib
        
        def sign_document(document, key):
            h = hashlib.sha1()
            h.update(document.encode())
            h.update(key.encode())
            return h.hexdigest()
        """,
        "Certificate fingerprint with SHA1" => """
        def get_cert_fingerprint(cert_data):
            return hashlib.sha1(cert_data).hexdigest()
        """,
        "HMAC with SHA1" => """
        import hmac
        import hashlib
        
        def create_hmac(message, secret):
            return hmac.new(secret.encode(), message.encode(), hashlib.sha1).hexdigest()
        """
      },
      fixed: %{
        "Use SHA-256 for signatures" => """
        import hashlib
        
        def sign_document(document, key):
            h = hashlib.sha256()
            h.update(document.encode())
            h.update(key.encode())
            return h.hexdigest()
        """,
        "Use SHA-256 for fingerprints" => """
        def get_cert_fingerprint(cert_data):
            return hashlib.sha256(cert_data).hexdigest()
        """,
        "Use HMAC-SHA256" => """
        import hmac
        import hashlib
        
        def create_hmac(message, secret):
            return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
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
      "https://shattered.io/",
      "https://www.nist.gov/news-events/news/2022/12/nist-retires-sha-1-cryptographic-algorithm"
    ]
  end

  @doc """
  Returns detailed vulnerability description.
  """
  def vulnerability_description do
    """
    SHA1 is a cryptographic hash function that is no longer considered secure for
    cryptographic purposes. It has known vulnerabilities:
    
    1. **Collision Attacks**: Researchers have demonstrated practical collision attacks
       against SHA1, creating two different files with the same SHA1 hash.
    
    2. **SHAttered Attack (2017)**: Google and CWI Amsterdam demonstrated the first
       practical SHA1 collision, creating two different PDF files with the same hash.
    
    3. **Theoretical Weaknesses**: SHA1's 160-bit output is too small by modern
       standards, making it vulnerable to brute force attacks.
    
    ## Real-World Impact
    
    - **Certificate Forgery**: SHA1 certificates can be forged
    - **Git Vulnerabilities**: Git's use of SHA1 has required mitigation strategies
    - **Digital Signatures**: SHA1 signatures can be compromised
    
    ## Migration Timeline
    
    - 2005: First theoretical attacks published
    - 2017: First practical collision demonstrated (SHAttered)
    - 2020: Most browsers reject SHA1 certificates
    - 2022: NIST formally deprecated SHA1
    
    ## Safe Alternatives
    
    - **SHA-256/SHA-3**: For general hashing needs
    - **SHA-512**: For higher security requirements
    - **BLAKE2**: Modern, fast alternative
    - **HMAC-SHA256**: For message authentication
    """
  end

  @doc """
  Returns AST enhancement rules for improved detection.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Python.WeakHashSha1.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:min_confidence, :rules]
      
      iex> enhancement = RsolvApi.Security.Patterns.Python.WeakHashSha1.ast_enhancement()
      iex> enhancement.min_confidence
      0.75
      
      iex> enhancement = RsolvApi.Security.Patterns.Python.WeakHashSha1.ast_enhancement()
      iex> length(enhancement.rules)
      2
  """
  def ast_enhancement do
    %{
      rules: [
        %{
          type: "context_check",
          description: "Check if SHA1 is used for git compatibility",
          checks: [
            "git_hash",
            "git_object",
            "legacy_system",
            "backward_compatibility"
          ]
        },
        %{
          type: "severity_increase",
          description: "Increase severity for security-critical usage",
          contexts: [
            "signature",
            "certificate",
            "hmac",
            "authentication",
            "integrity"
          ]
        }
      ],
      min_confidence: 0.75
    }
  end
end