defmodule Rsolv.Security.Patterns.Php.WeakCrypto do
  @moduledoc """
  Pattern for detecting weak cryptography vulnerabilities in PHP.
  
  This pattern identifies when PHP applications use deprecated cryptographic functions
  (mcrypt extension), weak algorithms (DES, 3DES), or insecure modes (ECB) that 
  compromise data confidentiality and integrity.
  
  ## Vulnerability Details
  
  Weak cryptography encompasses several critical security issues in PHP applications:
  
  1. **Deprecated mcrypt Extension**: The mcrypt extension was deprecated in PHP 7.1
     and removed in PHP 7.2 due to security vulnerabilities and lack of maintenance.
  2. **Weak Algorithms**: DES and 3DES are cryptographically broken with known attacks.
  3. **Insecure Modes**: ECB mode reveals patterns in encrypted data.
  4. **Legacy Functions**: Using outdated cryptographic implementations.
  
  ### Attack Example
  ```php
  // Vulnerable code - using deprecated mcrypt with weak DES algorithm
  $encrypted = mcrypt_encrypt(MCRYPT_DES, $key, $data, MCRYPT_MODE_ECB);
  
  // Also vulnerable - weak 3DES algorithm
  $cipher = mcrypt_encrypt(MCRYPT_3DES, $key, $plaintext, MCRYPT_MODE_CBC);
  
  // Vulnerable - ECB mode in OpenSSL (reveals patterns)
  $encrypted = openssl_encrypt($data, 'aes-128-ecb', $key);
  ```
  
  The mcrypt extension has multiple known vulnerabilities including improper
  key derivation, weak random number generation, and susceptibility to
  padding oracle attacks. Modern applications should use the OpenSSL
  extension with strong algorithms and secure modes.
  """
  
  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "php-weak-crypto",
      name: "Weak Cryptography",
      description: "Using deprecated or weak encryption algorithms",
      type: :weak_crypto,
      severity: :medium,
      languages: ["php"],
      regex: ~r/(mcrypt_[a-zA-Z_]+|MCRYPT_(?:DES|3DES|MODE_ECB)|(?:openssl_(?:en|de)crypt|\w+)\s*\([^,]*,?\s*['"][^'"]*(?:des|ecb)[^'"]*['"]|['"][^'"]*(?:des|ecb)[^'"]*['"])/i,
      cwe_id: "CWE-327",
      owasp_category: "A02:2021",
      recommendation: "Use OpenSSL extension with AES-256-GCM or ChaCha20-Poly1305",
      test_cases: %{
        vulnerable: [
          ~S|mcrypt_encrypt(MCRYPT_DES, $key, $data, MCRYPT_MODE_ECB);|,
          ~S|mcrypt_decrypt(MCRYPT_3DES, $key, $data, MCRYPT_MODE_CBC);|,
          ~S|openssl_encrypt($data, 'aes-128-ecb', $key);|,
          ~S|openssl_encrypt($data, 'des-cbc', $key);|
        ],
        safe: [
          ~S|openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv, $tag);|,
          ~S|openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);|,
          ~S|sodium_crypto_secretbox($message, $nonce, $key);|,
          ~S|random_bytes(32);|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Weak cryptography vulnerabilities occur when PHP applications use deprecated, broken, or 
      insufficiently secure cryptographic algorithms, functions, or configurations. This encompasses 
      several critical issues that can compromise data confidentiality, integrity, and authentication.
      
      The most common weak cryptography issues in PHP include:
      
      ### 1. Deprecated mcrypt Extension
      
      The mcrypt library was officially deprecated in PHP 7.1 and completely removed in PHP 7.2 
      due to numerous security vulnerabilities and lack of active maintenance. Applications still 
      using mcrypt functions are inherently vulnerable and cannot receive security updates.
      
      Key problems with mcrypt:
      - **Improper Key Derivation**: mcrypt doesn't provide secure key derivation functions
      - **Weak Random Number Generation**: Uses predictable randomness in some configurations  
      - **Padding Oracle Vulnerabilities**: Susceptible to padding oracle attacks in CBC mode
      - **No Authenticated Encryption**: Provides no integrity protection
      - **Unmaintained Codebase**: No security patches or updates since 2007
      
      ### 2. Cryptographically Broken Algorithms
      
      **Data Encryption Standard (DES)**:
      - 56-bit effective key size is trivially broken by modern hardware
      - Can be brute-forced in hours using commodity hardware
      - Officially deprecated by NIST since 2005
      - Vulnerable to differential and linear cryptanalysis
      
      **Triple DES (3DES)**:
      - Effective 112-bit security reduced to 80 bits due to meet-in-the-middle attacks
      - Slow performance compared to modern algorithms like AES
      - Deprecated by NIST, with complete phase-out mandated by 2023
      - Vulnerable to Sweet32 attacks when processing large amounts of data
      
      ### 3. Insecure Cipher Modes
      
      **Electronic Codebook (ECB) Mode**:
      - Encrypts identical plaintext blocks to identical ciphertext blocks
      - Reveals patterns in encrypted data (the "penguin problem")
      - Provides no semantic security for structured data
      - Vulnerable to known-plaintext and chosen-plaintext attacks
      - Should never be used for any real-world encryption
      
      ### 4. Implementation Vulnerabilities
      
      Even when using strong algorithms, improper implementation can introduce vulnerabilities:
      - **Missing Authentication**: Encryption without integrity protection enables tampering
      - **IV Reuse**: Reusing initialization vectors breaks semantic security
      - **Weak Key Generation**: Using predictable or low-entropy keys
      - **Side-Channel Attacks**: Timing attacks against string comparisons
      
      ### Real-World Impact
      
      Weak cryptography vulnerabilities have led to numerous high-profile breaches:
      - **Data Exposure**: Encrypted databases become readable when weak crypto is broken
      - **Session Hijacking**: Weak session encryption enables account takeover
      - **Financial Fraud**: Payment systems using weak crypto enable transaction manipulation
      - **Privacy Violations**: Personal data encrypted with weak algorithms becomes exposed
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
          type: :nist,
          id: "SP 800-57",
          title: "NIST Special Publication 800-57 - Cryptographic Key Management",
          url: "https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final"
        },
        %{
          type: :research,
          id: "mcrypt_deprecation",
          title: "PHP mcrypt Extension Deprecation and Security Issues",
          url: "https://www.php.net/manual/en/migration71.deprecated.php"
        },
        %{
          type: :research,
          id: "sweet32_attack",
          title: "Sweet32: Birthday attacks on 64-bit block ciphers in TLS and OpenVPN",
          url: "https://sweet32.info/"
        }
      ],
      attack_vectors: [
        "Brute force attacks against DES 56-bit keys using distributed computing",
        "Meet-in-the-middle attacks reducing 3DES security from 112 to 80 bits",
        "Pattern analysis attacks against ECB mode revealing data structure",
        "Sweet32 birthday attacks against 64-bit block ciphers with large data volumes",
        "Padding oracle attacks against CBC mode implementations without proper validation",
        "Known-plaintext attacks exploiting predictable data patterns in ECB mode",
        "Side-channel attacks against weak implementations (timing, power analysis)"
      ],
      real_world_impact: [
        "Complete data exposure when encrypted databases are compromised",
        "Session hijacking enabling unauthorized access to user accounts", 
        "Financial fraud through manipulation of encrypted payment data",
        "Compliance violations (PCI DSS, HIPAA, GDPR) due to insufficient encryption",
        "Intellectual property theft when weak crypto protects sensitive business data",
        "Privacy breaches exposing personal information due to broken encryption",
        "Regulatory fines and legal liability from using deprecated cryptographic standards"
      ],
      cve_examples: [
        %{
          id: "CVE-2016-10006",
          description: "mcrypt extension buffer overflow in mcrypt_generic function",
          severity: "high",
          cvss: 7.5,
          note: "Demonstrates why mcrypt extension was deprecated and removed"
        },
        %{
          id: "CVE-2017-9618", 
          description: "DES algorithm implementation vulnerability in OpenSSL",
          severity: "medium",
          cvss: 5.9,
          note: "Weakness in DES implementation affecting legacy cipher suites"
        },
        %{
          id: "CVE-2019-1547",
          description: "Side-channel attack against ECDSA with timing information",
          severity: "medium", 
          cvss: 4.7,
          note: "Example of implementation vulnerabilities in cryptographic code"
        },
        %{
          id: "CVE-2020-1967",
          description: "NULL pointer dereference in OpenSSL signature verification",
          severity: "high",
          cvss: 7.5,
          note: "Shows importance of keeping cryptographic libraries updated"
        },
        %{
          id: "CVE-2021-3711",
          description: "Buffer overrun in OpenSSL SM2 decryption",
          severity: "high",
          cvss: 9.8,
          note: "Critical vulnerability in cryptographic library affecting all applications"
        }
      ],
      detection_notes: """
      This pattern detects several categories of weak cryptography in PHP code:
      
      1. **mcrypt Function Usage**: Any use of mcrypt_ functions indicates deprecated cryptography
      2. **Weak Algorithm Constants**: MCRYPT_DES, MCRYPT_3DES indicate broken algorithms  
      3. **Insecure Mode Constants**: MCRYPT_MODE_ECB indicates insecure cipher mode
      4. **OpenSSL Weak Algorithms**: Detection of DES variants in openssl_encrypt/decrypt
      5. **ECB Mode in OpenSSL**: Detection of ECB mode usage in modern OpenSSL functions
      
      The regex pattern matches:
      - mcrypt function calls (mcrypt_encrypt, mcrypt_decrypt, etc.)
      - Weak algorithm constants (MCRYPT_DES, MCRYPT_3DES)  
      - Insecure mode constants (MCRYPT_MODE_ECB)
      - OpenSSL functions with weak algorithms ('des-cbc', 'des-ecb', etc.)
      - OpenSSL functions using ECB mode ('aes-128-ecb', etc.)
      
      Special attention is paid to:
      - Case-insensitive matching for algorithm names
      - Various quote styles for OpenSSL cipher names
      - Function parameter positioning for accurate detection
      """,
      safe_alternatives: [
        "Use OpenSSL extension with AES-256-GCM: openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv, $tag)",
        "Use ChaCha20-Poly1305 for authenticated encryption: openssl_encrypt($data, 'chacha20-poly1305', $key, 0, $iv, $tag)",
        "Use Sodium extension for modern cryptography: sodium_crypto_secretbox($message, $nonce, $key)",
        "Generate cryptographically secure random data: random_bytes(32)",
        "Use proper key derivation: hash_pbkdf2('sha256', $password, $salt, 10000, 32, true)",
        "Implement proper authenticated encryption with AEAD ciphers",
        "Use bcrypt or Argon2 for password hashing: password_hash($password, PASSWORD_ARGON2ID)"
      ],
      additional_context: %{
        common_mistakes: [
          "Continuing to use mcrypt after PHP 7.2 upgrade (will cause fatal errors)",
          "Believing that 3DES is 'secure enough' for non-critical data",
          "Using ECB mode because it's simpler (no IV management required)",
          "Implementing custom padding instead of using built-in PKCS#7",
          "Storing encryption keys in the same location as encrypted data",
          "Using predictable IVs or reusing IVs across encryptions",
          "Forgetting to authenticate encrypted data (encryption ≠ integrity)"
        ],
        migration_strategies: [
          "Replace mcrypt_encrypt() with openssl_encrypt() using AES-256-CBC + HMAC",
          "Upgrade to authenticated encryption modes (GCM, CCM) when available",
          "Implement proper key management and rotation procedures",
          "Use the Sodium extension for all new cryptographic code",
          "Validate and sanitize all cryptographic parameters",
          "Implement secure random number generation for keys and IVs",
          "Add integrity protection to all encrypted data"
        ],
        compliance_considerations: [
          "PCI DSS requires strong cryptography (AES minimum) for payment data",
          "HIPAA requires appropriate safeguards including strong encryption for PHI",
          "GDPR considers weak encryption as inadequate security measures",
          "NIST SP 800-57 provides guidelines for cryptographic key management",
          "FIPS 140-2 certification requirements for government applications"
        ]
      }
    }
  end

  @doc """
  Returns test cases for the weak cryptography pattern.
  
  ## Examples
  
      iex> test_cases = Rsolv.Security.Patterns.Php.WeakCrypto.test_cases()
      iex> length(test_cases.positive)
      8
      
      iex> test_cases = Rsolv.Security.Patterns.Php.WeakCrypto.test_cases()
      iex> length(test_cases.negative)
      6
  """
  def test_cases do
    %{
      positive: [
        %{
          code: ~S|mcrypt_encrypt(MCRYPT_DES, $key, $data, MCRYPT_MODE_ECB);|,
          description: "mcrypt with weak DES algorithm and insecure ECB mode"
        },
        %{
          code: ~S|mcrypt_decrypt(MCRYPT_3DES, $key, $data, MCRYPT_MODE_CBC);|,
          description: "mcrypt with deprecated 3DES algorithm"
        },
        %{
          code: ~S|mcrypt_generic($handle, $data);|,
          description: "Generic mcrypt function usage"
        },
        %{
          code: ~S|$cipher = MCRYPT_DES;|,
          description: "Assignment of weak DES algorithm constant"
        },
        %{
          code: ~S|$mode = MCRYPT_MODE_ECB;|,
          description: "Assignment of insecure ECB mode constant"
        },
        %{
          code: ~S|openssl_encrypt($data, 'aes-128-ecb', $key);|,
          description: "OpenSSL with insecure ECB mode"
        },
        %{
          code: ~S|openssl_encrypt($data, 'des-cbc', $key);|,
          description: "OpenSSL with weak DES algorithm"
        },
        %{
          code: ~S|openssl_decrypt($encrypted, 'des-ede3-ecb', $key);|,
          description: "OpenSSL decrypt with 3DES in ECB mode"
        }
      ],
      negative: [
        %{
          code: ~S|openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv, $tag);|,
          description: "Strong AES-256-GCM authenticated encryption"
        },
        %{
          code: ~S|openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);|,
          description: "Strong AES-256-CBC encryption with IV"
        },
        %{
          code: ~S|sodium_crypto_secretbox($message, $nonce, $key);|,
          description: "Modern Sodium library authenticated encryption"
        },
        %{
          code: ~S|$cipher = 'aes-256-ctr';|,
          description: "Strong AES algorithm assignment"
        },
        %{
          code: ~S|hash('sha256', $data);|,
          description: "Cryptographic hashing (not encryption)"
        },
        %{
          code: ~S|password_hash($password, PASSWORD_ARGON2ID);|,
          description: "Secure password hashing"
        }
      ]
    }
  end

  @doc """
  Returns examples of vulnerable and fixed code.
  
  ## Examples
  
      iex> examples = Rsolv.Security.Patterns.Php.WeakCrypto.examples()
      iex> Map.keys(examples)
      [:vulnerable, :fixed]
  """
  def examples do
    %{
      vulnerable: %{
        "mcrypt DES encryption" => """
        // VULNERABLE: Uses deprecated mcrypt with weak DES
        $key = 'secret12';
        $data = 'sensitive information';
        $encrypted = mcrypt_encrypt(MCRYPT_DES, $key, $data, MCRYPT_MODE_ECB);
        """,
        "3DES with predictable IV" => """
        // VULNERABLE: Weak 3DES algorithm with static IV
        $key = str_repeat('key', 8);
        $iv = str_repeat('\\0', 8);
        $encrypted = mcrypt_encrypt(MCRYPT_3DES, $key, $data, MCRYPT_MODE_CBC, $iv);
        """,
        "OpenSSL ECB mode" => """
        // VULNERABLE: Strong algorithm but insecure ECB mode
        $key = random_bytes(32);
        $encrypted = openssl_encrypt($sensitive_data, 'aes-256-ecb', $key);
        """
      },
      fixed: %{
        "Modern encryption" => """
        // SECURE: AES-256-GCM with proper key and IV generation
        $key = random_bytes(32);
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv, $tag);
        $result = base64_encode($iv . $tag . $encrypted);
        """,
        "Secure algorithms" => """
        // SECURE: ChaCha20-Poly1305 authenticated encryption
        $key = random_bytes(32);
        $iv = random_bytes(12);
        $encrypted = openssl_encrypt($data, 'chacha20-poly1305', $key, 0, $iv, $tag);
        """,
        "Sodium library" => """
        // SECURE: Modern Sodium library with XChaCha20-Poly1305
        $key = sodium_crypto_secretbox_keygen();
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $encrypted = sodium_crypto_secretbox($message, $nonce, $key);
        """
      }
    }
  end

  @doc """
  Returns educational description of the vulnerability.
  
  ## Examples
  
      iex> desc = Rsolv.Security.Patterns.Php.WeakCrypto.vulnerability_description()
      iex> desc =~ "Weak cryptography"
      true
      
      iex> desc = Rsolv.Security.Patterns.Php.WeakCrypto.vulnerability_description()
      iex> desc =~ "mcrypt"
      true
      
      iex> desc = Rsolv.Security.Patterns.Php.WeakCrypto.vulnerability_description()
      iex> desc =~ "deprecated"
      true
  """
  def vulnerability_description do
    """
    Weak cryptography vulnerabilities occur when applications use deprecated, broken, or 
    insufficiently secure cryptographic algorithms, implementations, or configurations.
    
    In PHP, this commonly manifests as:
    
    1. **mcrypt Extension Usage**: The mcrypt library was deprecated in PHP 7.1 and 
       removed in PHP 7.2 due to security vulnerabilities and lack of maintenance.
       
    2. **Weak Algorithms**: DES (56-bit keys) and 3DES are cryptographically broken 
       and can be attacked with modern computing power.
       
    3. **Insecure Modes**: ECB mode reveals patterns in encrypted data and should 
       never be used for real-world encryption.
       
    4. **Implementation Issues**: Poor key management, IV reuse, and missing 
       authentication enable various attacks.
    
    Modern PHP applications should use the OpenSSL extension with strong algorithms 
    like AES-256-GCM or the Sodium extension for authenticated encryption.
    """
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual vulnerabilities and false positives
  by analyzing cryptographic function usage, algorithm strength, and implementation context.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Php.WeakCrypto.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Php.WeakCrypto.ast_enhancement()
      iex> enhancement.min_confidence
      0.6
      
      iex> enhancement = Rsolv.Security.Patterns.Php.WeakCrypto.ast_enhancement()
      iex> length(enhancement.ast_rules)
      4
  """
  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.6,
      ast_rules: [
        %{
          type: "weak_crypto_functions",
          description: "Identify deprecated mcrypt and weak OpenSSL usage",
          functions: [
            "mcrypt_encrypt", "mcrypt_decrypt", "mcrypt_generic", 
            "mdecrypt_generic", "mcrypt_module_open", "mcrypt_module_close",
            "openssl_encrypt", "openssl_decrypt"
          ]
        },
        %{
          type: "crypto_algorithm_analysis", 
          description: "Analyze cryptographic algorithm strength",
          weak_algorithms: ["DES", "3DES", "MCRYPT_DES", "MCRYPT_3DES"],
          weak_modes: ["ECB", "MCRYPT_MODE_ECB"],
          strong_algorithms: ["AES-256-GCM", "AES-256-CBC", "ChaCha20-Poly1305"]
        },
        %{
          type: "context_validation",
          description: "Validate cryptographic implementation context",
          exclude_patterns: [
            "test", "mock", "example", "demo", "benchmark",
            "migration", "legacy_support", "compatibility"
          ]
        },
        %{
          type: "modern_crypto_detection",
          description: "Detect usage of modern cryptographic libraries",
          safe_prefixes: ["sodium_crypto_", "random_bytes", "hash_pbkdf2"],
          weak_prefixes: ["mcrypt_", "crypt", "md5", "sha1"]
        }
      ]
    }
  end
end
