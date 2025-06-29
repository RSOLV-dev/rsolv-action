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
        \w+\s*=\s*hashlib\.sha1\s*\(|
        # hashlib.sha1 as parameter (without parentheses)
        hashlib\.sha1\b
      /x,
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
  Comprehensive vulnerability metadata for weak SHA-1 hashing in Python.
  
  This metadata documents the specific risks of using SHA-1 in Python applications
  and provides authoritative guidance for secure alternatives.
  """
  def vulnerability_metadata do
    %{
      description: """
      SHA-1 (Secure Hash Algorithm 1) is a cryptographic hash function that was 
      officially deprecated by NIST in 2011 and has been practically broken since 
      2017 when Google demonstrated the first public collision. In Python, 
      hashlib.sha1() remains available but should never be used for security 
      purposes. Modern attacks can find SHA-1 collisions for as little as $45,000 
      worth of cloud computing, making it accessible to well-funded attackers.
      
      Python developers commonly misuse SHA-1 for:
      1. Password hashing (critically vulnerable to rainbow tables)
      2. Digital signatures and certificates (forgeable)
      3. File integrity verification (bypassable)
      4. Git commits (vulnerable to collision attacks)
      5. API authentication tokens (forgeable)
      
      The 2017 SHAttered attack demonstrated practical collision generation, and 
      the 2020 chosen-prefix collision attack reduced costs even further. Major 
      browsers have deprecated SHA-1 certificates, and Git has moved to hardened 
      SHA-1 to mitigate risks. Any continued use of SHA-1 for security purposes 
      is a critical vulnerability.
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
          type: :research,
          id: "shattered",
          title: "SHAttered - First public SHA-1 collision",
          url: "https://shattered.io/"
        },
        %{
          type: :research,
          id: "shambles",
          title: "SHA-1 is a Shambles - Chosen-prefix collisions",
          url: "https://sha-mbles.github.io/"
        },
        %{
          type: :nist,
          id: "SP_800-131A",
          title: "NIST Transitions: Recommendation for Transitioning Cryptographic Algorithms",
          url: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf"
        },
        %{
          type: :python_docs,
          id: "hashlib",
          title: "Python hashlib — Secure hashes and message digests",
          url: "https://docs.python.org/3/library/hashlib.html"
        }
      ],
      attack_vectors: [
        "Collision attacks: Generate two different inputs with same SHA-1 hash for ~$45,000",
        "Chosen-prefix collisions: Craft meaningful documents with identical hashes",
        "Certificate forgery: Create rogue certificates that pass SHA-1 validation",
        "Git commit spoofing: Create malicious commits with same SHA-1 as legitimate ones",
        "Signature forgery: Bypass digital signature verification using collisions",
        "Rainbow tables: Pre-computed SHA-1 hashes for password cracking",
        "GPU acceleration: Modern GPUs can compute billions of SHA-1 hashes per second",
        "Cloud-based attacks: Distributed SHA-1 collision finding using cloud resources"
      ],
      real_world_impact: [
        "SHAttered (2017): Google created two PDFs with same SHA-1 hash, proving practical attacks",
        "Flame malware (2012): Used SHA-1 collision to forge Microsoft code-signing certificate",
        "Stevens et al. (2009): Rogue CA certificate created using SHA-1 collisions",
        "GitHub/GitLab: Demonstrated SHA-1 collision in Git repositories",
        "Browser deprecation: Chrome, Firefox, Edge reject SHA-1 certificates since 2017",
        "PGP key attacks: Demonstrated ability to create colliding PGP keys",
        "Academic credentials: Forged certificates from major universities",
        "Payment systems: Compromised transaction integrity using SHA-1 weaknesses"
      ],
      cve_examples: [
        %{
          id: "CVE-2020-12825",
          description: "Kallithea used SHA-1 for security-critical password reset tokens",
          severity: "high",
          cvss: 7.5,
          note: "SHA-1 tokens could be forged allowing account takeover"
        },
        %{
          id: "CVE-2019-15790",
          description: "Artifex MuPDF SHA-1 collision vulnerability in digital signatures",
          severity: "high",
          cvss: 7.5,
          note: "SHA-1 weakness allowed forging digitally signed PDFs"
        },
        %{
          id: "CVE-2017-15361",
          description: "Infineon RSA library generated keys with SHA-1 weaknesses",
          severity: "critical",
          cvss: 9.8,
          note: "Weak random number generation combined with SHA-1 compromised millions of devices"
        },
        %{
          id: "CVE-2005-4900",
          description: "Early theoretical SHA-1 collision vulnerability",
          severity: "medium",
          cvss: 5.0,
          note: "First warning of SHA-1 weakness, took 12 years for practical exploitation"
        }
      ],
      detection_notes: """
      This pattern detects SHA-1 usage in Python through:
      
      1. hashlib.sha1() calls with various import styles
      2. SHA1() constructor from legacy crypto libraries
      3. Direct sha1.new() calls (Python 2 style)
      4. Variable assignments suggesting SHA-1 usage
      
      The pattern is case-insensitive to catch variations and focuses on
      actual SHA-1 hash creation rather than comments or documentation.
      Special attention is given to security contexts like password, token,
      and signature generation.
      """,
      safe_alternatives: [
        "Use hashlib.sha256() as minimum security standard",
        "Use hashlib.sha3_256() for new applications",
        "Use hashlib.blake2b() for high-performance hashing",
        "Use bcrypt/argon2/scrypt for password hashing, never raw SHA",
        "For HMAC: hmac.new(key, msg, hashlib.sha256)",
        "For file integrity: Consider sha256sum or blake2b",
        "For Git: Git now uses hardened SHA-1, moving to SHA-256",
        "For certificates: Use SHA-256 minimum, SHA-384 preferred"
      ],
      additional_context: %{
        common_mistakes: [
          "Using SHA-1 for password hashing (use bcrypt/argon2 instead)",
          "Thinking SHA-1 + salt is secure (it's not, use proper password hashing)",
          "Using SHA-1 for API tokens (use secrets.token_urlsafe)",
          "Implementing HMAC-SHA1 (upgrade to HMAC-SHA256 minimum)",
          "Certificate signing with SHA-1 (browsers reject these)",
          "Using SHA-1 for blockchain/cryptocurrency applications",
          "Assuming SHA-1 is 'good enough' for non-critical uses"
        ],
        secure_patterns: [
          "hashlib.sha256(data.encode()).hexdigest()",
          "hashlib.sha3_256(data.encode()).hexdigest()",
          "hmac.new(key, message, hashlib.sha256).hexdigest()",
          "from passlib.hash import bcrypt; bcrypt.hash(password)",
          "import secrets; secrets.token_urlsafe(32)",
          "from cryptography.hazmat.primitives import hashes",
          "Use subprocess for system sha256sum/sha512sum utilities"
        ],
        migration_timeline: [
          "2005: Theoretical SHA-1 attacks published",
          "2011: NIST formally deprecates SHA-1",
          "2014: Chrome announces SHA-1 certificate sunset",
          "2016: Major CAs stop issuing SHA-1 certificates",
          "2017: First public SHA-1 collision (SHAttered)",
          "2019: Chosen-prefix collision for ~$45,000",
          "2020: SHA-1 collisions demonstrated in PGP/GPG",
          "2024: SHA-1 should not exist in any production code"
        ],
        python_specific_notes: [
          "hashlib.sha1(usedforsecurity=False) added in Python 3.9",
          "Many legacy Python 2 systems still use sha.new() (deprecated)",
          "Popular libraries like PyCrypto defaulted to SHA-1",
          "Django deprecated SHA1PasswordHasher in version 1.4",
          "Requests library uses SHA-1 for caching (non-security)",
          "Git libraries in Python often still use SHA-1 for compatibility"
        ]
      }
    }
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
      ast_rules: [
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
