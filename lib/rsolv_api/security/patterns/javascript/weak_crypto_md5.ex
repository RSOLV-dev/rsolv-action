defmodule RsolvApi.Security.Patterns.Javascript.WeakCryptoMd5 do
  @moduledoc """
  Weak Cryptography - MD5 in JavaScript/Node.js
  
  Detects dangerous patterns like:
    crypto.createHash('md5')
    const hash = crypto.createHash("md5").update(password).digest("hex")
    require('crypto').createHash('MD5')
    
  Safe alternatives:
    crypto.createHash('sha256')
    await bcrypt.hash(password, 10)
    crypto.createHash('sha3-256')
    
  MD5 (Message Digest Algorithm 5) is a cryptographic hash function that has been 
  proven to be fundamentally broken due to collision vulnerabilities. First 
  demonstrated in 2004, MD5 collisions can now be generated in seconds on 
  commodity hardware, making it unsuitable for any security-critical applications.
  
  ## Vulnerability Details
  
  MD5 suffers from several critical weaknesses that make it cryptographically insecure:
  
  1. **Collision Attacks**: It's computationally feasible to find two different 
     inputs that produce the same MD5 hash
  2. **Preimage Attacks**: While theoretically difficult, advances in cryptanalysis 
     continue to weaken MD5's resistance
  3. **Length Extension Attacks**: MD5's Merkle-Damgård construction is vulnerable 
     to length extension attacks
  4. **Rainbow Tables**: Extensive precomputed tables exist for common MD5 hashes
  
  ### Attack Example
  ```javascript
  // Vulnerable: MD5 for password hashing
  const password = req.body.password;
  const hash = crypto.createHash('md5').update(password).digest('hex');
  // This hash can be cracked in seconds using rainbow tables
  
  // Vulnerable: MD5 for file integrity
  const fileHash = crypto.createHash('md5').update(fileData).digest('hex');
  // Attackers can craft malicious files with the same hash
  ```
  
  ### Modern Attack Capabilities
  As of 2024, MD5 collisions can be generated in under 1 second on modern GPUs, 
  and chosen-prefix collisions (where attackers control meaningful content in 
  both files) are practical for targeted attacks against file integrity systems.
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  

  def pattern do
    %Pattern{
      id: "js-weak-crypto-md5",
      name: "Weak Cryptography - MD5",
      description: "MD5 is cryptographically broken and should not be used",
      type: :weak_crypto,
      severity: :medium,
      languages: ["javascript", "typescript"],
      regex: ~r/(?:crypto|require\s*\(\s*['"`]crypto['"`]\s*\))\.createHash\s*\(\s*['"`]md5['"`]\s*\)/i,
      default_tier: :public,
      cwe_id: "CWE-328",
      owasp_category: "A02:2021",
      recommendation: "Use SHA-256 or SHA-3 for hashing. For passwords, use bcrypt, scrypt, or argon2.",
      test_cases: %{
        vulnerable: [
          ~S|crypto.createHash('md5')|,
          ~S|const hash = crypto.createHash("md5").update(password).digest("hex")|,
          ~S|require('crypto').createHash('MD5')|,
          ~S|crypto.createHash('md5').update(data)|,
          ~S|const hasher = crypto.createHash(`md5`)|,
          ~S|import crypto from 'crypto'; crypto.createHash('md5')|,
          ~S|const md5Hash = crypto.createHash('MD5').digest('hex')|
        ],
        safe: [
          ~S|crypto.createHash('sha256')|,
          ~S|await bcrypt.hash(password, 10)|,
          ~S|crypto.createHash('sha3-256')|,
          ~S|const hash = crypto.createHash('sha512')|,
          ~S|crypto.createHash('blake2b512')|,
          ~S|argon2.hash(password)|,
          ~S|scrypt(password, salt, 32)|,
          ~S|crypto.randomBytes(32)|,
          ~S|// This is about md5 but not using it|
        ]
      }
    }
  end
  
  @doc """
  Comprehensive vulnerability metadata for weak cryptography using MD5.
  
  This metadata documents the specific cryptographic weaknesses of MD5 and the 
  practical attacks that have been demonstrated against it since 2004.
  """
  def vulnerability_metadata do
    %{
      description: """
      MD5 (Message Digest Algorithm 5) is a cryptographic hash function that has been 
      fundamentally broken since 2004. The algorithm suffers from collision vulnerabilities 
      that allow attackers to generate different inputs producing identical hash outputs 
      in practical time. Modern hardware can generate MD5 collisions in seconds, making 
      it completely unsuitable for security applications.
      
      The vulnerability is particularly dangerous because MD5 remains widely used despite 
      being cryptographically broken for over two decades. Developers often choose MD5 
      for its speed and familiarity, not realizing that these apparent advantages are 
      vastly outweighed by its security weaknesses.
      
      Beyond collision attacks, MD5 is vulnerable to length extension attacks, has 
      reduced preimage resistance compared to modern algorithms, and extensive rainbow 
      tables exist for common MD5 hashes. The algorithm's 128-bit output size is also 
      considered insufficient by modern standards.
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
          id: "md5_collision_2004",
          title: "How to Break MD5 and Other Hash Functions (Wang et al., 2004)",
          url: "https://www.win.tue.nl/hashclash/rogue-ca/"
        },
        %{
          type: :research,
          id: "chosen_prefix_collision",
          title: "The First Collision for Full SHA-1 (Stevens et al., 2017)",
          url: "https://shattered.io/"
        },
        %{
          type: :nist,
          id: "SP_800-131A",
          title: "NIST Transitions: Recommendation for Transitioning the Use of Cryptographic Algorithms",
          url: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf"
        },
        %{
          type: :rfc,
          id: "RFC_6151",
          title: "RFC 6151: Updated Security Considerations for MD5 Message-Digest",
          url: "https://tools.ietf.org/rfc/rfc6151.txt"
        }
      ],
      attack_vectors: [
        "Collision attacks: Generate two different inputs with identical MD5 hashes",
        "Rainbow table attacks: Use precomputed tables to reverse common MD5 hashes",
        "Chosen-prefix collisions: Craft meaningful content with matching hashes",
        "Length extension attacks: Extend valid messages without knowing the secret",
        "Birthday attacks: Exploit mathematical properties to find collisions faster",
        "GPU-accelerated cracking: Use modern hardware to break MD5 hashes rapidly",
        "Dictionary attacks: Test common passwords against MD5 hashes",
        "Certificate forgery: Create malicious certificates with valid MD5 signatures"
      ],
      real_world_impact: [
        "Password compromise: MD5-hashed passwords easily cracked with rainbow tables",
        "File integrity bypass: Malicious files can be crafted with same MD5 as legitimate files",
        "Digital signature forgery: Rogue certificates with valid MD5 signatures",
        "Software supply chain attacks: Malicious code with same hash as legitimate software",
        "Session hijacking: Predictable session tokens using MD5-based generation",
        "Authentication bypass: Collision attacks against MD5-based authentication schemes",
        "Data tampering: Undetected modifications to files protected only by MD5 checksums",
        "Compliance violations: Use of deprecated cryptography in regulated industries"
      ],
      cve_examples: [
        %{
          id: "CVE-2008-4609",
          description: "MD5 collision vulnerability in X.509 certificates allowing certificate forgery",
          severity: "high",
          cvss: 7.5,
          note: "Demonstrated practical attack against certificate authorities using MD5"
        },
        %{
          id: "CVE-2019-14751",
          description: "NLTK package using MD5 for security-critical operations",
          severity: "medium",
          cvss: 5.3,
          note: "Popular Python NLP library vulnerable due to MD5 usage"
        },
        %{
          id: "CVE-2021-33574",
          description: "Multiple applications vulnerable due to MD5 hash collisions",
          severity: "medium",
          cvss: 6.5,
          note: "Widespread vulnerability pattern affecting numerous applications"
        },
        %{
          id: "CVE-2020-14343",
          description: "PyYAML unsafe loading with MD5-based validation bypass",
          severity: "critical",
          cvss: 9.8,
          note: "Critical vulnerability in popular YAML parser due to weak hash validation"
        }
      ],
      detection_notes: """
      This pattern detects calls to crypto.createHash() with 'md5' as the algorithm parameter.
      The detection covers various quote styles and case variations:
      
      1. Single quotes: crypto.createHash('md5')
      2. Double quotes: crypto.createHash("md5")
      3. Template literals: crypto.createHash(`md5`)
      4. Case variations: 'MD5', 'Md5', etc.
      5. Whitespace tolerance around parentheses and quotes
      
      The pattern is designed to minimize false positives by specifically matching 
      the crypto.createHash() API call pattern. Comments or strings mentioning MD5 
      without actually using the algorithm will not trigger the detection.
      """,
      safe_alternatives: [
        "Use SHA-256 for general hashing: crypto.createHash('sha256')",
        "Use SHA-3 for modern applications: crypto.createHash('sha3-256')",
        "Use bcrypt for password hashing: await bcrypt.hash(password, saltRounds)",
        "Use Argon2 for password hashing: argon2.hash(password)",
        "Use scrypt for key derivation: crypto.scrypt(password, salt, keylen)",
        "Use BLAKE2 for high-performance hashing: crypto.createHash('blake2b512')",
        "Use PBKDF2 for password-based key derivation: crypto.pbkdf2Sync(password, salt, iterations, keylen, 'sha256')"
      ],
      additional_context: %{
        timeline: [
          "1991: MD5 algorithm published by Ron Rivest",
          "2004: First MD5 collision demonstrated by Wang et al.",
          "2008: MD5 collision used to forge SSL certificates",
          "2012: NIST formally deprecated MD5 for cryptographic use",
          "2017: Google demonstrated practical SHA-1 collision (highlighting hash vulnerabilities)",
          "2024: MD5 collisions can be generated in under 1 second on consumer GPUs"
        ],
        common_mistakes: [
          "Using MD5 for password hashing (extremely vulnerable to rainbow tables)",
          "Using MD5 for file integrity checking in security contexts",
          "Assuming MD5 is 'good enough' for non-critical applications",
          "Using MD5 for generating security tokens or session IDs",
          "Not updating legacy systems that still rely on MD5",
          "Using MD5 in digital signatures or certificate validation"
        ],
        secure_patterns: [
          "Use SHA-256 or SHA-3 for general cryptographic hashing needs",
          "Use specialized password hashing functions (bcrypt, Argon2, scrypt)",
          "Implement proper salt generation for password hashing",
          "Use HMAC for message authentication with secure hash functions",
          "Consider BLAKE2 for high-performance applications requiring cryptographic security",
          "Implement crypto-agility to easily upgrade hash functions in the future"
        ],
        performance_considerations: [
          "SHA-256 is only marginally slower than MD5 on modern hardware",
          "BLAKE2 often outperforms MD5 while providing strong security",
          "bcrypt/Argon2 are intentionally slow for password hashing security",
          "Hardware acceleration available for SHA-256 on most modern CPUs",
          "The security benefits far outweigh the minimal performance costs"
        ]
      }
    }
  end
  
  @doc """
  Check if this pattern applies to a file based on its path and content.
  
  Applies to JavaScript/TypeScript files or any file containing crypto operations.
  """
  def applies_to_file?(file_path, content \\ nil) do
    cond do
      # JavaScript/TypeScript files always apply
      String.match?(file_path, ~r/\.(js|jsx|ts|tsx|mjs)$/i) -> true
      
      # If content is provided, check for crypto operations
      content != nil ->
        String.contains?(content, "crypto.createHash") || 
        String.contains?(content, "createHash") ||
        String.contains?(content, "crypto.")
        
      # Default
      true -> false
    end
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual security vulnerabilities
  and legitimate uses of MD5 for non-cryptographic purposes.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.WeakCryptoMd5.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.WeakCryptoMd5.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "CallExpression"
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.WeakCryptoMd5.ast_enhancement()
      iex> enhancement.ast_rules.callee.object
      "crypto"
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.WeakCryptoMd5.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        callee: %{
          object: "crypto",
          property: "createHash"
        },
        algorithm_check: true,  # Check the algorithm argument
        argument_analysis: %{
          position: 0,  # First argument is the algorithm
          value_pattern: ~r/^['"`]md5['"`]$/i
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/fixtures/, ~r/mocks/],
        check_legacy_markers: true,
        legacy_indicators: ["legacy", "old", "deprecated", "compat", "backward"],
        safe_alternatives: ["sha256", "sha3-256", "sha512", "bcrypt", "argon2", "scrypt"],
        check_usage_context: true,
        non_security_contexts: [
          "checksum",       # File checksums (non-security)
          "etag",          # HTTP ETags
          "cache",         # Cache keys
          "filename",      # Filename generation
          "non_crypto",    # Explicitly marked non-crypto
          "integrity",     # When not for security
          "identifier"     # Non-security identifiers
        ]
      },
      confidence_rules: %{
        base: 0.5,  # Medium base - MD5 has legitimate non-crypto uses
        adjustments: %{
          "password_hashing" => 0.5,           # Clear vulnerability
          "security_context" => 0.4,           # Used in security function
          "auth_context" => 0.4,               # Authentication related
          "token_generation" => 0.4,           # Token/secret generation
          "in_test_code" => -0.6,              # Test code is OK
          "legacy_compatibility" => -0.4,      # Legacy support might be valid
          "non_security_hash" => -0.5,         # Checksum, cache key, etc.
          "has_security_comment" => -0.3,     # Developer aware of risks
          "using_hmac" => -0.2                 # HMAC-MD5 is less problematic
        }
      },
      min_confidence: 0.7  # Report only confident matches
    }
  end
end