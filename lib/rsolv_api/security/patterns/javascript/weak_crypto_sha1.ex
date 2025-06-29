defmodule RsolvApi.Security.Patterns.Javascript.WeakCryptoSha1 do
  @moduledoc """
  Weak Cryptography - SHA1 in JavaScript/Node.js
  
  Detects dangerous patterns like:
    crypto.createHash('sha1')
    const hash = crypto.createHash("sha1").update(data).digest()
    crypto.createHash('SHA1')
    
  Safe alternatives:
    crypto.createHash('sha256')
    crypto.createHash('sha3-256')
    crypto.createHash('sha512')
    
  SHA1 (Secure Hash Algorithm 1) is a cryptographic hash function that has been 
  deprecated due to collision vulnerabilities. While not as severely broken as MD5, 
  SHA1 has been successfully attacked in practice, most notably by Google's 
  demonstration in 2017 that showed practical collision attacks are feasible.
  
  ## Vulnerability Details
  
  SHA1 suffers from several cryptographic weaknesses that make it unsuitable for 
  security-critical applications:
  
  1. **Collision Attacks**: Google demonstrated the first practical SHA1 collision 
     in 2017 with the SHAttered attack, requiring 2^63.1 operations
  2. **Chosen-prefix Collisions**: More advanced attacks that allow meaningful 
     content control in both colliding documents
  3. **Length Extension Attacks**: SHA1's Merkle-Damgård construction remains 
     vulnerable to length extension attacks
  4. **Deprecation by Standards Bodies**: NIST deprecated SHA1 for digital 
     signatures in 2011, and major browsers stopped accepting SHA1 certificates
  
  ### Attack Example
  ```javascript
  // Vulnerable: SHA1 for digital signatures
  const signature = crypto.createHash('sha1').update(document).digest('hex');
  // This signature can potentially be forged through collision attacks
  
  // Vulnerable: SHA1 for password hashing
  const passwordHash = crypto.createHash('sha1').update(password + salt).digest('hex');
  // While better than MD5, still vulnerable to rainbow tables and collision attacks
  ```
  
  ### SHAttered Impact (2017)
  Google's SHAttered attack demonstrated that SHA1 collisions are not just 
  theoretical but practically achievable. This breakthrough showed that two 
  different PDF files could be crafted with identical SHA1 hashes, proving 
  that SHA1 can no longer be trusted for integrity verification or digital signatures.
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  def pattern do
    %Pattern{
      id: "js-weak-crypto-sha1",
      name: "Weak Cryptography - SHA1",
      description: "SHA1 is vulnerable to collision attacks",
      type: :weak_crypto,
      severity: :medium,
      languages: ["javascript", "typescript"],
      regex: ~r/(?:crypto|require\s*\(\s*['"`]crypto['"`]\s*\))\.createHash\s*\(\s*['"`]sha-?1['"`]\s*\)/i,
      cwe_id: "CWE-328",
      owasp_category: "A02:2021",
      recommendation: "Use SHA-256 or SHA-3 instead of SHA1.",
      test_cases: %{
        vulnerable: [
          ~S|crypto.createHash('sha1')|,
          ~S|const hash = crypto.createHash("sha1").update(data).digest()|,
          ~S|crypto.createHash('SHA1')|,
          ~S|require('crypto').createHash('sha1')|,
          ~S|const hasher = crypto.createHash(`sha1`)|,
          ~S|import crypto from 'crypto'; crypto.createHash('sha1').digest('hex')|,
          ~S|const sha1Hash = crypto.createHash('SHA-1').update(password)|
        ],
        safe: [
          ~S|crypto.createHash('sha256')|,
          ~S|crypto.createHash('sha3-256')|,
          ~S|const hash = crypto.createHash('sha512')|,
          ~S|crypto.createHash('blake2b512')|,
          ~S|await bcrypt.hash(password, 10)|,
          ~S|argon2.hash(password)|,
          ~S|scrypt(password, salt, 32)|,
          ~S|crypto.randomBytes(32)|,
          ~S|// This talks about sha1 but doesn't use it|,
          ~S|const comment = "sha1 is deprecated"|
        ]
      }
    }
  end
  
  @doc """
  Comprehensive vulnerability metadata for weak cryptography using SHA1.
  
  This metadata documents the specific cryptographic weaknesses of SHA1 and the 
  practical attacks that have been demonstrated, particularly Google's SHAttered attack in 2017.
  """
  def vulnerability_metadata do
    %{
      description: """
      SHA1 (Secure Hash Algorithm 1) is a cryptographic hash function that has been 
      deprecated due to demonstrated collision vulnerabilities. While initially considered 
      secure, advances in cryptanalysis and computational power have made collision attacks 
      against SHA1 practically feasible. The most significant breakthrough was Google's 
      SHAttered attack in 2017, which demonstrated the first practical SHA1 collision.
      
      Unlike MD5, which has been completely broken for decades, SHA1 maintained theoretical 
      security until recent years. However, the combination of improved attack techniques 
      and increased computational resources has made SHA1 collisions achievable within 
      reasonable time and budget constraints. This has led to widespread deprecation of 
      SHA1 across the industry.
      
      The vulnerability is particularly concerning for digital signatures, file integrity 
      verification, and certificate validation, where collision attacks can be used to 
      create malicious content with valid signatures or certificates. While password 
      hashing with SHA1 is less immediately vulnerable to collision attacks, it remains 
      susceptible to rainbow table attacks and lacks the computational hardness required 
      for secure password storage.
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
          id: "shattered_attack",
          title: "The First Collision for Full SHA-1 (Stevens et al., 2017)",
          url: "https://shattered.io/"
        },
        %{
          type: :research,
          id: "sha1_cryptanalysis",
          title: "Finding a Collision in the Full SHA-1 (Wang et al., 2005)",
          url: "https://www.iacr.org/archive/crypto2005/36210017/36210017.pdf"
        },
        %{
          type: :nist,
          id: "SP_800-131A",
          title: "NIST Transitions: Recommendation for Transitioning the Use of Cryptographic Algorithms",
          url: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf"
        },
        %{
          type: :rfc,
          id: "RFC_6194",
          title: "RFC 6194: Security Considerations for the SHA-0 and SHA-1 Message-Digest Algorithms",
          url: "https://tools.ietf.org/rfc/rfc6194.txt"
        }
      ],
      attack_vectors: [
        "Collision attacks: Generate two different inputs with identical SHA1 hashes (SHAttered)",
        "Chosen-prefix collisions: Craft meaningful content with matching hashes",
        "Rainbow table attacks: Use precomputed tables for common SHA1 hashes",
        "Length extension attacks: Extend valid messages without knowing the secret",
        "Certificate forgery: Create malicious certificates with valid SHA1 signatures",
        "Document forgery: Create malicious documents with same hash as legitimate ones",
        "Software integrity bypass: Malicious code with same SHA1 as legitimate software",
        "Git commit manipulation: Craft malicious commits with identical SHA1 hashes"
      ],
      real_world_impact: [
        "Digital signature bypass: Malicious documents can be created with valid signatures",
        "Certificate authority compromise: Rogue certificates with valid SHA1 signatures",
        "Software supply chain attacks: Malicious updates with same hash as legitimate software",
        "Version control system manipulation: Crafted commits that appear legitimate",
        "File integrity system bypass: Malicious files replacing legitimate ones undetected",
        "Password compromise: SHA1-hashed passwords vulnerable to rainbow table attacks",
        "Compliance violations: Use of deprecated cryptography in regulated industries",
        "Browser security warnings: Modern browsers reject SHA1 certificates"
      ],
      cve_examples: [
        %{
          id: "CVE-2017-15042",
          description: "SHA1 collision vulnerability in Git allowing history manipulation",
          severity: "medium",
          cvss: 5.5,
          note: "Exploitation of SHA1 weaknesses in version control systems"
        },
        %{
          id: "CVE-2020-1967",
          description: "OpenSSL SHA1 signature verification bypass",
          severity: "high",
          cvss: 7.4,
          note: "SHA1 signature validation vulnerabilities in cryptographic libraries"
        },
        %{
          id: "CVE-2016-2108",
          description: "ASN.1 BIO SHA1 signature verification bypass",
          severity: "high",
          cvss: 8.1,
          note: "Demonstrates practical exploitation of SHA1 weaknesses"
        },
        %{
          id: "CVE-2018-18623", 
          description: "Grafana SHA1-based password reset token vulnerability",
          severity: "medium",
          cvss: 6.5,
          note: "Application-level vulnerability due to SHA1 usage in security tokens"
        }
      ],
      detection_notes: """
      This pattern detects calls to crypto.createHash() with 'sha1' or 'sha-1' as the algorithm parameter.
      The detection covers various variations and cases:
      
      1. Standard naming: 'sha1', 'SHA1'
      2. Hyphenated form: 'sha-1', 'SHA-1'  
      3. Quote styles: single quotes, double quotes, template literals
      4. Module patterns: crypto.createHash() and require('crypto').createHash()
      5. Case insensitive matching to catch all variations
      
      The pattern specifically targets the crypto.createHash() API to minimize false 
      positives while ensuring comprehensive coverage of SHA1 usage patterns in Node.js applications.
      """,
      safe_alternatives: [
        "Use SHA-256 for general hashing: crypto.createHash('sha256')",
        "Use SHA-3 for modern applications: crypto.createHash('sha3-256')",
        "Use SHA-512 for higher security: crypto.createHash('sha512')",
        "Use bcrypt for password hashing: await bcrypt.hash(password, saltRounds)",
        "Use Argon2 for password hashing: argon2.hash(password)",
        "Use BLAKE2 for high-performance hashing: crypto.createHash('blake2b512')",
        "Use HMAC-SHA256 for message authentication: crypto.createHmac('sha256', key)"
      ],
      additional_context: %{
        timeline: [
          "1995: SHA1 algorithm published by NIST as FIPS 180-1",
          "2005: Theoretical collision attack published by Wang et al.",
          "2011: NIST deprecated SHA1 for digital signatures",
          "2014: Google announced plans to deprecate SHA1 in Chrome",
          "2016: Major browsers stopped accepting SHA1 certificates",
          "2017: Google demonstrated first practical SHA1 collision (SHAttered)",
          "2019: Chosen-prefix collision attacks made practical",
          "2024: SHA1 collisions achievable for under $50,000"
        ],
        shattered_attack_details: [
          "Required 2^63.1 SHA1 operations (vs 2^80 brute force)",
          "Used 6,500 years of CPU computation and 110 years of GPU computation",
          "Demonstrated with two different PDF files having identical SHA1 hashes",
          "Proved that SHA1 collision attacks are practically feasible",
          "Led to immediate deprecation of SHA1 across the industry"
        ],
        common_mistakes: [
          "Assuming SHA1 is 'good enough' because it's better than MD5",
          "Using SHA1 for password hashing (vulnerable to rainbow tables)",
          "Not updating legacy systems that rely on SHA1 for integrity",
          "Using SHA1 in new applications despite widespread deprecation",
          "Believing collision attacks are only theoretical threats",
          "Not considering the computational cost reduction over time"
        ],
        secure_patterns: [
          "Use SHA-256 or SHA-3 for general cryptographic hashing",
          "Use specialized password hashing functions (bcrypt, Argon2, scrypt)",
          "Implement crypto-agility for easy algorithm upgrades",
          "Use HMAC with secure hash functions for message authentication",
          "Consider BLAKE2 for high-performance cryptographic applications",
          "Regular security audits to identify and replace deprecated algorithms"
        ],
        performance_impact: [
          "SHA-256 performance is comparable to SHA1 on modern hardware",
          "BLAKE2 often outperforms SHA1 while providing better security",
          "Hardware acceleration widely available for SHA-256",
          "The security benefits significantly outweigh minimal performance costs",
          "Modern CPUs have built-in instructions for SHA-256 operations"
        ]
      }
    }
  end
  
  @doc """
  Check if this pattern applies to a file based on its path and content.
  
  Applies to JavaScript/TypeScript files or any file containing crypto operations.
  """
  def applies_to_file?(file_path, content ) do
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
  and legitimate uses of SHA1 for non-cryptographic purposes.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.WeakCryptoSha1.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.WeakCryptoSha1.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "CallExpression"
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.WeakCryptoSha1.ast_enhancement()
      iex> enhancement.ast_rules.callee.object
      "crypto"
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.WeakCryptoSha1.ast_enhancement()
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
          value_pattern: ~r/^['"`]sha-?1['"`]$/i
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/fixtures/, ~r/mocks/],
        check_legacy_markers: true,
        legacy_indicators: ["legacy", "old", "deprecated", "compat", "backward", "migration"],
        safe_alternatives: ["sha256", "sha3-256", "sha512", "sha384", "blake2b512"],
        check_usage_context: true,
        non_security_contexts: [
          "git",           # Git uses SHA1 for commits
          "checksum",      # Non-security checksums
          "cache",         # Cache keys
          "identifier",    # Non-security identifiers
          "webpack",       # Build tools often use SHA1
          "test",          # Test fixtures
          "example"        # Example code
        ]
      },
      confidence_rules: %{
        base: 0.5,  # Medium base - SHA1 has some legitimate uses
        adjustments: %{
          "password_hashing" => 0.5,           # Clear vulnerability
          "security_context" => 0.4,           # Used in security function
          "signature_generation" => 0.5,       # Digital signatures vulnerable
          "certificate_validation" => 0.5,     # Certificate usage dangerous
          "in_test_code" => -0.6,              # Test code is OK
          "git_sha_usage" => -0.7,             # Git SHA1 usage is expected
          "build_tool_context" => -0.5,       # Webpack, rollup, etc.
          "legacy_compatibility" => -0.3,      # Legacy support might be valid
          "non_security_hash" => -0.4,         # Non-security use cases
          "has_migration_comment" => -0.3      # Developer planning to migrate
        }
      },
      min_confidence: 0.7  # Report only confident matches
    }
  end
end
