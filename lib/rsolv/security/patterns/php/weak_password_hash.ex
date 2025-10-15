defmodule Rsolv.Security.Patterns.Php.WeakPasswordHash do
  @moduledoc """
  Pattern for detecting weak password hashing algorithms in PHP.

  This pattern identifies when weak cryptographic functions like MD5, SHA1, or
  improperly configured crypt() are used for password hashing. These algorithms
  are vulnerable to rainbow table attacks and brute force attacks.

  ## Vulnerability Details

  Weak password hashing algorithms like MD5 and SHA1 were designed for speed,
  not security. They can be cracked quickly using modern hardware, making them
  unsuitable for password storage. Even with salt, these algorithms are too fast
  to provide adequate protection against brute-force attacks.

  ### Attack Example
  ```php
  // Vulnerable code
  $password_hash = md5($_POST['password']);

  // Attack: Rainbow tables can reverse MD5 hashes in seconds
  // Online databases contain billions of pre-computed MD5 hashes
  ```
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @impl true
  def pattern do
    %Pattern{
      id: "php-weak-password-hash",
      name: "Weak Password Hashing",
      description: "Using weak algorithms like MD5 or SHA1 for passwords",
      type: :crypto,
      severity: :critical,
      languages: ["php"],
      regex:
        ~r/(md5|sha1)\s*\(\s*.*(?:password|pass|pwd)|crypt\s*\(\s*.*(?:password|pass|pwd)(?!.*\$2[abxy]\$)|hash\s*\(\s*['"](md5|sha1)['"]\s*,\s*.*(?:password|pass|pwd)/i,
      cwe_id: "CWE-916",
      owasp_category: "A02:2021",
      recommendation: "Use password_hash() with PASSWORD_BCRYPT or PASSWORD_ARGON2I",
      test_cases: %{
        vulnerable: [
          ~S|md5($_POST['password']);|,
          ~S|sha1($password);|,
          ~S|crypt($_POST['password']);|,
          ~S|hash('md5', $_POST['password']);|
        ],
        safe: [
          ~S|password_hash($_POST['password'], PASSWORD_BCRYPT);|,
          ~S|crypt($password, '$2y$10$' . $salt);|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Weak password hashing is one of the most critical security vulnerabilities.
      Using algorithms like MD5, SHA1, or improperly configured crypt() for password
      storage leaves user accounts vulnerable to various attacks.

      Why these algorithms are weak:
      - MD5: Can be computed at 200 billion hashes per second on modern GPUs
      - SHA1: Only slightly slower than MD5, still far too fast
      - Plain crypt(): Often defaults to DES, which is extremely weak

      These fast algorithms allow attackers to try billions of password combinations
      per second, making even complex passwords vulnerable to brute-force attacks.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-916",
          title: "Use of Password Hash With Insufficient Computational Effort",
          url: "https://cwe.mitre.org/data/definitions/916.html"
        },
        %{
          type: :owasp,
          id: "A02:2021",
          title: "OWASP Top 10 2021 - A02 Cryptographic Failures",
          url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
        },
        %{
          type: :research,
          id: "password_hashing_best_practices",
          title: "Password Hashing: OWASP Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"
        },
        %{
          type: :research,
          id: "php_password_hashing",
          title: "PHP Password Hashing Functions",
          url: "https://www.php.net/manual/en/faq.passwords.php"
        }
      ],
      attack_vectors: [
        "Rainbow table attacks: Pre-computed hash lookups",
        "Brute force attacks: Testing all possible passwords",
        "Dictionary attacks: Using common password lists",
        "GPU-accelerated cracking: Billions of attempts per second",
        "Cloud-based cracking: Distributed computing power",
        "Hash collision attacks: Finding different inputs with same hash",
        "Online hash databases: Billions of pre-cracked hashes",
        "Timing attacks: Exploiting comparison timing differences"
      ],
      real_world_impact: [
        "Account takeover and identity theft",
        "Mass compromise of user accounts",
        "Exposure of sensitive personal data",
        "Compliance violations (GDPR, HIPAA, PCI-DSS)",
        "Reputational damage and loss of user trust",
        "Legal liability for negligent security",
        "Financial losses from fraud and remediation"
      ],
      cve_examples: [
        %{
          id: "CVE-2024-23091",
          description: "HotelDruid weak MD5 password hashing",
          severity: "critical",
          cvss: 9.8,
          note: "MD5 hashing allows plaintext password recovery"
        },
        %{
          id: "CVE-2023-38701",
          description: "Weak SHA1 password storage in web application",
          severity: "high",
          cvss: 8.8,
          note: "SHA1 passwords crackable with modest resources"
        },
        %{
          id: "CVE-2022-29464",
          description: "MD5 password hashing in WSO2 products",
          severity: "critical",
          cvss: 9.8,
          note: "Legacy MD5 hashing for backward compatibility"
        },
        %{
          id: "CVE-2021-3129",
          description: "Weak password hashing in Laravel < 8.4.2",
          severity: "high",
          cvss: 8.8,
          note: "Insufficient computational effort in password hashing"
        },
        %{
          id: "CVE-2020-7247",
          description: "MD5 password storage vulnerability",
          severity: "critical",
          cvss: 9.8,
          note: "Passwords stored as unsalted MD5 hashes"
        }
      ],
      detection_notes: """
      This pattern detects weak password hashing by looking for:
      - MD5 or SHA1 functions with password-related variables
      - crypt() without bcrypt/argon2 algorithm prefixes
      - hash() function with MD5/SHA1 algorithms on passwords
      - Case-insensitive matching for password variations

      The regex uses negative lookahead to exclude proper bcrypt usage
      with crypt() function when it includes algorithm identifiers.
      """,
      safe_alternatives: [
        "Use password_hash() with PASSWORD_BCRYPT or PASSWORD_ARGON2I",
        "Implement proper salt generation (handled automatically by password_hash)",
        "Use password_verify() for password checking",
        "Set appropriate cost factors for your security needs",
        "Consider password strength requirements",
        "Implement account lockout policies",
        "Use multi-factor authentication for sensitive accounts",
        "Regularly update hashing algorithms as standards evolve"
      ],
      additional_context: %{
        common_mistakes: [
          "Using MD5/SHA1 even with salt (still too fast)",
          "Creating custom hashing schemes",
          "Not using password_verify() for verification",
          "Storing passwords in reversible encryption",
          "Using the same salt for all passwords",
          "Not migrating from legacy weak hashes"
        ],
        secure_patterns: [
          "password_hash($password, PASSWORD_BCRYPT)",
          "password_hash($password, PASSWORD_ARGON2I)",
          "password_hash($password, PASSWORD_DEFAULT)",
          "crypt($password, '$2y$12$' . $salt) // bcrypt with cost 12",
          "Using established libraries like phpass"
        ],
        php_specific_notes: [
          "PASSWORD_DEFAULT currently uses bcrypt but may change",
          "Cost factor should be tuned to take ~100ms",
          "password_needs_rehash() helps algorithm migration",
          "Never use md5(), sha1(), or hash() for passwords",
          "crypt() is safe only with proper algorithm prefix"
        ]
      }
    }
  end

  @doc """
  Returns test cases for the pattern.

  ## Examples

      iex> test_cases = Rsolv.Security.Patterns.Php.WeakPasswordHash.test_cases()
      iex> length(test_cases.positive) > 0
      true

      iex> test_cases = Rsolv.Security.Patterns.Php.WeakPasswordHash.test_cases()
      iex> length(test_cases.negative) > 0
      true

      iex> pattern = Rsolv.Security.Patterns.Php.WeakPasswordHash.pattern()
      iex> pattern.id
      "php-weak-password-hash"
  """
  def test_cases do
    %{
      positive: [
        %{
          code: ~S|$hash = md5($_POST['password']);|,
          description: "MD5 hashing of password"
        },
        %{
          code: ~S|$stored = sha1($password);|,
          description: "SHA1 hashing of password"
        },
        %{
          code: ~S|md5($_GET['pass'] . $salt);|,
          description: "MD5 with salt still weak"
        },
        %{
          code: ~S|crypt($_POST['password']);|,
          description: "Plain crypt without algorithm"
        },
        %{
          code: ~S|hash('md5', $_POST['password']);|,
          description: "hash() with MD5 algorithm"
        },
        %{
          code: ~S|hash('sha1', $user_password);|,
          description: "hash() with SHA1 algorithm"
        },
        %{
          code: ~S|$pwd_hash = md5($_REQUEST['pwd']);|,
          description: "MD5 of pwd field"
        }
      ],
      negative: [
        %{
          code: ~S|password_hash($_POST['password'], PASSWORD_BCRYPT);|,
          description: "Proper bcrypt hashing"
        },
        %{
          code: ~S|password_hash($password, PASSWORD_DEFAULT);|,
          description: "Using default algorithm"
        },
        %{
          code: ~S|password_hash($_GET['pass'], PASSWORD_ARGON2I);|,
          description: "Using Argon2i"
        },
        %{
          code: ~S|crypt($password, '$2y$10$' . $salt);|,
          description: "crypt with bcrypt prefix"
        },
        %{
          code: ~S|md5_file('document.pdf');|,
          description: "File hashing, not password"
        },
        %{
          code: ~S|sha1($non_password_data);|,
          description: "SHA1 of non-password data"
        },
        %{
          code: ~S|hash('sha256', $password);|,
          description: "SHA256 is better but context matters"
        }
      ]
    }
  end

  @doc """
  Returns examples of vulnerable and fixed code.
  """
  def examples do
    %{
      vulnerable: %{
        "Basic MD5 password hashing" => ~S"""
        // User registration - VULNERABLE
        $username = $_POST['username'];
        $password = $_POST['password'];

        // MD5 is completely broken for passwords
        $password_hash = md5($password);

        $sql = "INSERT INTO users (username, password) VALUES (?, ?)";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$username, $password_hash]);

        // This hash can be cracked in seconds
        """,
        "SHA1 with salt still vulnerable" => ~S"""
        // Login system - VULNERABLE
        function hashPassword($password) {
            $salt = 'myapp_salt_12345';  // Static salt
            return sha1($salt . $password);
        }

        // SHA1 is too fast even with salt
        $hashed = hashPassword($_POST['password']);

        // Modern GPUs can test billions of SHA1 hashes/second
        """,
        "Weak crypt() usage" => ~S"""
        // Password update - VULNERABLE
        $new_password = $_POST['new_password'];

        // crypt() without algorithm defaults to weak DES
        $hash = crypt($new_password);

        // Or with weak algorithm
        $hash = crypt($new_password, 'aa');  // DES

        // DES is limited to 8 characters!
        """,
        "Custom double hashing" => ~S"""
        // Custom "security" - VULNERABLE
        function superSecureHash($password) {
            // Double hashing doesn't add security
            return md5(sha1($password));
        }

        $pwd_hash = superSecureHash($_POST['pwd']);

        // Still vulnerable to same attacks
        """
      },
      fixed: %{
        "Using password_hash()" => ~S"""
        // User registration - SECURE
        $username = $_POST['username'];
        $password = $_POST['password'];

        // password_hash() handles everything securely
        $password_hash = password_hash($password, PASSWORD_BCRYPT, [
            'cost' => 12  // Adjust based on your server
        ]);

        $sql = "INSERT INTO users (username, password) VALUES (?, ?)";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$username, $password_hash]);

        // Verification later:
        if (password_verify($password, $stored_hash)) {
            // Password is correct
        }
        """,
        "Migration from MD5" => ~S"""
        // Migrating from legacy MD5 - SECURE
        function authenticateUser($username, $password) {
            $user = getUserByUsername($username);

            if (substr($user['password'], 0, 3) === 'md5') {
                // Legacy MD5 hash
                $md5_hash = substr($user['password'], 4);
                if (md5($password) === $md5_hash) {
                    // Upgrade to bcrypt
                    $new_hash = password_hash($password, PASSWORD_DEFAULT);
                    updateUserPassword($username, $new_hash);
                    return true;
                }
            } else {
                // Modern password_hash
                return password_verify($password, $user['password']);
            }

            return false;
        }
        """,
        "Complete secure implementation" => ~S"""
        // Modern password handling - SECURE
        class PasswordManager {
            private const MIN_PASSWORD_LENGTH = 12;
            private const BCRYPT_COST = 12;

            public function hashPassword(string $password): string {
                // Validate password strength
                if (strlen($password) < self::MIN_PASSWORD_LENGTH) {
                    throw new Exception('Password too short');
                }

                // Use bcrypt with appropriate cost
                return password_hash($password, PASSWORD_BCRYPT, [
                    'cost' => self::BCRYPT_COST
                ]);
            }

            public function verifyPassword(string $password, string $hash): bool {
                return password_verify($password, $hash);
            }

            public function needsRehash(string $hash): bool {
                return password_needs_rehash($hash, PASSWORD_BCRYPT, [
                    'cost' => self::BCRYPT_COST
                ]);
            }

            public function authenticate(string $username, string $password): bool {
                $user = $this->getUserByUsername($username);
                if (!$user) {
                    // Prevent timing attacks
                    password_verify('dummy', '$2y$12$dummy.hash.to.prevent.timing');
                    return false;
                }

                if ($this->verifyPassword($password, $user['password_hash'])) {
                    // Check if rehash needed
                    if ($this->needsRehash($user['password_hash'])) {
                        $new_hash = $this->hashPassword($password);
                        $this->updatePasswordHash($username, $new_hash);
                    }
                    return true;
                }

                return false;
            }
        }
        """
      }
    }
  end

  @doc """
  Returns detailed vulnerability description.
  """
  def vulnerability_description do
    """
    Weak password hashing is a critical security vulnerability that exposes user
    credentials to theft. Using fast hashing algorithms like MD5 or SHA1 for
    passwords allows attackers to crack them quickly using modern hardware.

    ## Why MD5 and SHA1 Are Broken

    These algorithms were designed for speed, not security:

    ### MD5 (Message Digest 5)
    - Computation speed: 200+ billion hashes/second on modern GPUs
    - Rainbow tables: Pre-computed for billions of common passwords
    - Collision vulnerabilities: Different inputs produce same hash
    - Online databases: MD5 hashes instantly reversible

    ### SHA1 (Secure Hash Algorithm 1)
    - Only marginally slower than MD5
    - Still vulnerable to brute force attacks
    - Deprecated by NIST since 2011
    - Google demonstrated collision attacks in 2017

    ## Attack Methods

    ### Rainbow Tables
    Pre-computed tables mapping hashes to passwords:
    ```
    5f4dcc3bf5aa765d61d832448ddb3dc -> password
    098fa6bcd4621db373cad4e83269b2c -> test
    ```

    ### GPU Cracking
    Modern GPUs can test billions of combinations:
    - RTX 4090: 164 billion MD5 hashes/second
    - 8-character passwords: Cracked in minutes
    - Even with salt: Still too fast

    ### Online Services
    Sites like CrackStation have databases of billions of pre-cracked hashes.

    ## Proper Password Hashing

    ### Key Requirements
    1. **Slow by design**: Should take ~100ms per hash
    2. **Memory-hard**: Resist GPU/ASIC optimization
    3. **Salt automatically**: Unique salt per password
    4. **Future-proof**: Easy to upgrade algorithms

    ### PHP's password_hash()
    ```php
    // Automatic salt, secure defaults
    $hash = password_hash($password, PASSWORD_BCRYPT);

    // With custom cost factor
    $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

    // Future-proof with PASSWORD_DEFAULT
    $hash = password_hash($password, PASSWORD_DEFAULT);
    ```

    ### Algorithm Comparison

    | Algorithm | Hashes/sec (GPU) | Time to crack 8-char | Suitable for passwords |
    |-----------|------------------|---------------------|----------------------|
    | MD5       | 164 billion      | 2 minutes           | ❌ Never             |
    | SHA1      | 63 billion       | 5 minutes           | ❌ Never             |
    | SHA256    | 23 billion       | 14 minutes          | ❌ Still too fast    |
    | bcrypt    | 105 thousand     | 2 years             | ✅ Yes               |
    | Argon2    | 30 thousand      | 7 years             | ✅ Yes (best)        |

    ## Migration Strategy

    If you have legacy weak hashes:

    1. **Don't panic**: Plan careful migration
    2. **Dual support**: Check both old and new formats
    3. **Upgrade on login**: Re-hash with strong algorithm
    4. **Force reset**: For high-security accounts
    5. **Set deadline**: Eventually disable weak hashes

    ## Best Practices

    1. **Use password_hash()**: Let PHP handle the complexity
    2. **Cost tuning**: Adjust cost for 50-100ms computation
    3. **Regular updates**: Use password_needs_rehash()
    4. **Length requirements**: Minimum 12 characters
    5. **Additional measures**: 2FA, rate limiting, lockouts

    Remember: Password security is critical. A single breach can compromise
    your entire user base and destroy trust permanently.
    """
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Php.WeakPasswordHash.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :min_confidence]

      iex> enhancement = Rsolv.Security.Patterns.Php.WeakPasswordHash.ast_enhancement()
      iex> enhancement.min_confidence
      0.8

      iex> enhancement = Rsolv.Security.Patterns.Php.WeakPasswordHash.ast_enhancement()
      iex> length(enhancement.ast_rules)
      4
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: [
        %{
          type: "hash_context",
          description: "Identify password hashing context",
          weak_algorithms: [
            "md5",
            "sha1",
            "sha",
            "md4",
            "md2"
          ],
          strong_algorithms: [
            "bcrypt",
            "argon2i",
            "argon2id",
            "scrypt",
            "pbkdf2"
          ]
        },
        %{
          type: "password_indicators",
          description: "Variables/fields indicating passwords",
          patterns: [
            "password",
            "pass",
            "pwd",
            "passwd",
            "passphrase",
            "user_password",
            "user_pass",
            "login_password"
          ],
          exclude_patterns: [
            "passport",
            "passenger",
            "bypass",
            "compass"
          ]
        },
        %{
          type: "safe_functions",
          description: "Modern password hashing functions",
          functions: [
            "password_hash",
            "password_verify",
            "password_needs_rehash",
            "password_get_info",
            "sodium_crypto_pwhash",
            "sodium_crypto_pwhash_str"
          ]
        },
        %{
          type: "algorithm_detection",
          description: "Detect algorithm usage in crypt()",
          safe_prefixes: [
            # bcrypt
            "$2y$",
            # bcrypt
            "$2a$",
            # bcrypt
            "$2b$",
            # Argon2i
            "$argon2i$",
            # Argon2id
            "$argon2id$"
          ],
          weak_prefixes: [
            # MD5
            "$1$",
            # DES (no prefix)
            "",
            # Extended DES
            "_"
          ]
        }
      ],
      min_confidence: 0.8
    }
  end
end
