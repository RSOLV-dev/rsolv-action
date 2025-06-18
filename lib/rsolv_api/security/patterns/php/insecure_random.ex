defmodule RsolvApi.Security.Patterns.Php.InsecureRandom do
  @moduledoc """
  Pattern for detecting insecure random number generation in PHP.
  
  This pattern identifies when weak random number functions like rand(), mt_rand(),
  or their seeding functions (srand(), mt_srand()) are used for security-sensitive
  purposes. These functions are predictable and should not be used for cryptographic
  or security-critical random values.
  
  ## Vulnerability Details
  
  PHP's rand() and mt_rand() functions use predictable algorithms that are unsuitable
  for security purposes. Attackers can predict future values by observing previous
  outputs, making tokens, session IDs, and passwords generated with these functions
  vulnerable to attack.
  
  ### Attack Example
  ```php
  // Vulnerable code
  $session_id = mt_rand(100000, 999999);
  $token = bin2hex(rand());
  
  // These values can be predicted by attackers who observe
  // a few previous outputs from the same process
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "php-insecure-random",
      name: "Insecure Random Number Generation",
      description: "Using predictable random functions for security purposes",
      type: :insecure_random,
      severity: :medium,
      languages: ["php"],
      regex: ~r/(rand|mt_rand|srand|mt_srand)\s*\(/,
      default_tier: :ai,
      cwe_id: "CWE-338",
      owasp_category: "A02:2021",
      recommendation: "Use random_bytes() or random_int() for cryptographic randomness",
      test_cases: %{
        vulnerable: [
          ~S|$token = rand(1000, 9999);|,
          ~S|$session_id = mt_rand();|,
          ~S|srand(time());|,
          ~S|mt_srand(12345);|
        ],
        safe: [
          ~S|$token = random_int(1000, 9999);|,
          ~S|$bytes = random_bytes(16);|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Insecure random number generation using predictable functions creates serious
      security vulnerabilities. PHP's rand() and mt_rand() functions use algorithms
      designed for statistical purposes, not cryptographic security. These functions
      produce predictable sequences that attackers can exploit to compromise tokens,
      session IDs, passwords, and other security-critical values.
      
      The core problems with these functions:
      - Mersenne Twister (mt_rand) has a period of 2^19937-1 but is completely predictable
      - Linear Congruential Generators (rand) are even weaker and easily reversed
      - Both functions can be seeded predictably using timestamps or process IDs
      - Future values can be calculated once the internal state is known
      
      Modern attacks can predict the next values after observing just a few outputs,
      making any security mechanism based on these functions fundamentally broken.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-338",
          title: "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
          url: "https://cwe.mitre.org/data/definitions/338.html"
        },
        %{
          type: :owasp,
          id: "A02:2021",
          title: "OWASP Top 10 2021 - A02 Cryptographic Failures",
          url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
        },
        %{
          type: :cwe,
          id: "CWE-330",
          title: "Use of Insufficiently Random Values",
          url: "https://cwe.mitre.org/data/definitions/330.html"
        },
        %{
          type: :research,
          id: "php_random_security",
          title: "Secure Randomness in PHP - Soliant Consulting",
          url: "https://www.soliantconsulting.com/blog/secure-randomness-php/"
        }
      ],
      attack_vectors: [
        "State recovery: Analyze mt_rand() outputs to determine internal state",
        "Timing attacks: Use predictable seeding based on timestamps",
        "Brute force: Try all possible seeds within reasonable time windows",
        "Pattern analysis: Detect statistical biases in weak generators",
        "Birthday attacks: Exploit collisions in short random values",
        "Replay attacks: Reuse predictable tokens across sessions",
        "Session hijacking: Predict session IDs using weak randomness",
        "Password prediction: Exploit predictable password generation"
      ],
      real_world_impact: [
        "Session hijacking through predictable session IDs",
        "Account takeover via guessable password reset tokens",
        "API key prediction and unauthorized access",
        "CSRF token bypass in web applications",
        "Cryptographic key compromise in weak implementations",
        "Gambling fraud through predictable random numbers",
        "Authentication bypass via token prediction",
        "Data breach through compromised encryption keys"
      ],
      cve_examples: [
        %{
          id: "CVE-2021-22948",
          description: "Session ID vulnerability in revive-adserver using uniqid()",
          severity: "high",
          cvss: 7.5,
          note: "Predictable session IDs based on microsecond timestamps"
        },
        %{
          id: "CVE-2024-21495",
          description: "Insecure randomness in github.com/greenpau/caddy-security",
          severity: "medium",
          cvss: 5.3,
          note: "Weak random number generator for security tokens"
        },
        %{
          id: "CVE-2023-3247",
          description: "Insufficiently random values in php-common",
          severity: "medium",
          cvss: 5.9,
          note: "Weak PRNG implementation affecting cryptographic operations"
        },
        %{
          id: "CVE-2021-3538",
          description: "Predictable UUID generation due to insecure randomness",
          severity: "medium",
          cvss: 5.3,
          note: "Insecure g.rand.Read function making UUIDs predictable"
        }
      ],
      detection_notes: """
      This pattern detects insecure random number generation by looking for:
      - rand() function calls which use weak LCG algorithms
      - mt_rand() function calls which use predictable Mersenne Twister
      - srand() and mt_srand() seeding functions with predictable seeds
      - Any usage context where these functions might generate security values
      
      The regex matches function calls but context analysis is needed to determine
      if the usage is security-sensitive vs. statistical/gaming purposes.
      """,
      safe_alternatives: [
        "Use random_int() for cryptographically secure integers",
        "Use random_bytes() for cryptographically secure byte strings",
        "Use openssl_random_pseudo_bytes() for backward compatibility",
        "Use password_hash() for password generation (includes secure salt)",
        "Use hash_pbkdf2() or password_hash() for key derivation",
        "Use bin2hex(random_bytes()) for hexadecimal tokens",
        "Use base64_encode(random_bytes()) for base64 tokens",
        "Use mcrypt_create_iv() on older PHP versions (deprecated)"
      ],
      additional_context: %{
        common_mistakes: [
          "Using mt_rand() thinking it's 'more secure' than rand()",
          "Seeding with time() believing it adds security",
          "Using modulo operation on rand() output (introduces bias)",
          "Combining multiple weak random sources",
          "Using uniqid() for security tokens (time-based)",
          "Believing that large ranges make weak generators secure"
        ],
        secure_patterns: [
          "random_int($min, $max) for secure integer ranges",
          "bin2hex(random_bytes($length)) for hex tokens",
          "base64_encode(random_bytes($length)) for base64 tokens",
          "password_hash($password, PASSWORD_DEFAULT) for passwords",
          "openssl_random_pseudo_bytes($length) for legacy support"
        ],
        php_version_notes: [
          "PHP 7.0+ introduced random_int() and random_bytes()",
          "PHP 7.1 made rand() an alias of mt_rand() (still weak)",
          "PHP 8.2 added Xoshiro256StarStar algorithm option",
          "Earlier versions require OpenSSL extension for secure randomness",
          "random_compat polyfill available for PHP 5.x compatibility"
        ]
      }
    }
  end
  
  @doc """
  Returns test cases for the pattern.
  
  ## Examples
  
      iex> test_cases = RsolvApi.Security.Patterns.Php.InsecureRandom.test_cases()
      iex> length(test_cases.positive) > 0
      true
      
      iex> test_cases = RsolvApi.Security.Patterns.Php.InsecureRandom.test_cases()
      iex> length(test_cases.negative) > 0
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Php.InsecureRandom.pattern()
      iex> pattern.id
      "php-insecure-random"
  """
  def test_cases do
    %{
      positive: [
        %{
          code: ~S|$token = rand(1000, 9999);|,
          description: "Basic rand() usage for token"
        },
        %{
          code: ~S|$session_id = mt_rand();|,
          description: "mt_rand() for session ID"
        },
        %{
          code: ~S|$nonce = mt_rand(100000, 999999);|,
          description: "mt_rand() with range for nonce"
        },
        %{
          code: ~S|srand(time());|,
          description: "Seeding with timestamp"
        },
        %{
          code: ~S|mt_srand(12345);|,
          description: "Fixed seed for mt_rand"
        },
        %{
          code: ~S|$code = rand(10, 99);|,
          description: "Short random code"
        }
      ],
      negative: [
        %{
          code: ~S|$token = random_int(1000, 9999);|,
          description: "Secure random integer"
        },
        %{
          code: ~S|$bytes = random_bytes(16);|,
          description: "Secure random bytes"
        },
        %{
          code: ~S|$token = bin2hex(random_bytes(32));|,
          description: "Secure hex token"
        },
        %{
          code: ~S|$secret = openssl_random_pseudo_bytes(16);|,
          description: "OpenSSL random bytes"
        },
        %{
          code: ~S|// rand() is insecure for security|,
          description: "Commented code"
        },
        %{
          code: ~S|$hash = password_hash($password, PASSWORD_DEFAULT);|,
          description: "Secure password hashing"
        },
        %{
          code: ~S|function randomFunction() { return 42; }|,
          description: "Function name containing 'rand'"
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
        "Session ID generation" => ~S"""
        // Session management - VULNERABLE
        session_start();
        if (!isset($_SESSION['user_id'])) {
            // Generate session-based user identifier
            $_SESSION['user_id'] = mt_rand(100000, 999999);
            $_SESSION['session_token'] = md5(mt_rand() . time());
        }
        
        // These values are predictable and can be guessed by attackers
        // who observe a few previous session IDs from the same server
        """,
        "Password reset tokens" => ~S"""
        // Password reset - VULNERABLE  
        function generateResetToken($user_id) {
            // Seed with predictable values
            srand(time() + $user_id);
            
            $token = '';
            for ($i = 0; $i < 32; $i++) {
                $token .= dechex(rand(0, 15));
            }
            
            return $token;
        }
        
        $reset_token = generateResetToken($user['id']);
        // Token can be predicted by knowing user ID and approximate time
        """,
        "API key generation" => ~S"""
        // API key generation - VULNERABLE
        class ApiKeyGenerator {
            public function generateKey() {
                $prefix = 'sk_';
                $timestamp = time();
                
                // Use timestamp as seed
                mt_srand($timestamp);
                
                $random_part = '';
                for ($i = 0; $i < 24; $i++) {
                    $random_part .= chr(65 + mt_rand(0, 25)); // A-Z
                }
                
                return $prefix . $timestamp . '_' . $random_part;
            }
        }
        
        // Attacker can predict keys by knowing generation time
        """,
        "CSRF token generation" => ~S"""
        // CSRF protection - VULNERABLE
        function generateCSRFToken() {
            // Simple but predictable token
            return md5(uniqid(rand(), true));
        }
        
        // Include in forms
        echo '<input type="hidden" name="csrf_token" value="' . 
             generateCSRFToken() . '">';
        
        // uniqid() with rand() seed is predictable
        """
      },
      fixed: %{
        "Using random_int()" => ~S"""
        // Session ID generation - SECURE
        session_start();
        if (!isset($_SESSION['user_id'])) {
            // Generate cryptographically secure identifier
            $_SESSION['user_id'] = random_int(100000, 999999);
            $_SESSION['session_token'] = bin2hex(random_bytes(32));
        }
        
        // These values are unpredictable and cryptographically secure
        """,
        "Using random_bytes()" => ~S"""
        // Password reset tokens - SECURE
        function generateResetToken($user_id) {
            // Generate cryptographically secure token
            $token = bin2hex(random_bytes(32));
            
            // Store with expiration
            $expires = time() + 3600; // 1 hour
            storeResetToken($user_id, $token, $expires);
            
            return $token;
        }
        
        $reset_token = generateResetToken($user['id']);
        // Token is unpredictable and secure
        """,
        "Secure API key generation" => ~S"""
        // API key generation - SECURE
        class SecureApiKeyGenerator {
            public function generateKey() {
                $prefix = 'sk_';
                
                // Generate truly random component
                $random_bytes = random_bytes(32);
                $random_part = base64_encode($random_bytes);
                
                // Make URL-safe
                $random_part = strtr($random_part, '+/', '-_');
                $random_part = rtrim($random_part, '=');
                
                return $prefix . $random_part;
            }
        }
        
        // Keys are unpredictable and secure
        """,
        "Secure CSRF tokens" => ~S"""
        // CSRF protection - SECURE
        function generateCSRFToken() {
            // Generate cryptographically secure token
            return bin2hex(random_bytes(32));
        }
        
        function verifyCSRFToken($token) {
            $expected = $_SESSION['csrf_token'] ?? '';
            
            // Constant-time comparison to prevent timing attacks
            return hash_equals($expected, $token);
        }
        
        // Store in session
        $_SESSION['csrf_token'] = generateCSRFToken();
        
        // Include in forms
        echo '<input type="hidden" name="csrf_token" value="' . 
             $_SESSION['csrf_token'] . '">';
        
        // Verify on form submission
        if (!verifyCSRFToken($_POST['csrf_token'])) {
            die('CSRF token verification failed');
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
    Insecure random number generation is a critical security vulnerability that
    undermines the foundation of many security mechanisms. When applications use
    predictable random number generators for security-sensitive values, they
    create opportunities for attackers to predict and manipulate these values.
    
    ## The Problem with Predictable Randomness
    
    ### PHP's Weak Random Functions
    
    #### rand() Function
    - Based on Linear Congruential Generator (LCG)
    - Completely deterministic sequence once state is known
    - Period varies by system but typically 2^31-1
    - Can be broken with just a few observed outputs
    
    #### mt_rand() Function
    - Based on Mersenne Twister algorithm
    - 19,937-bit internal state with period 2^19,937-1
    - Designed for statistical simulation, not cryptography
    - State can be recovered from 624 consecutive outputs
    - Predictable seeding makes it vulnerable even with fewer outputs
    
    #### Seeding Functions
    - srand() and mt_srand() with predictable seeds
    - Common seeds: time(), getmypid(), combination of both
    - Attackers can guess seeds within reasonable ranges
    - Once seed is known, entire sequence is predictable
    
    ## Attack Scenarios
    
    ### Session Hijacking
    ```php
    // Vulnerable session ID generation
    $session_id = 'sess_' . mt_rand(100000, 999999);
    ```
    Attackers can:
    1. Observe several session IDs from the same server
    2. Determine the mt_rand() internal state
    3. Predict future session IDs
    4. Hijack other users' sessions
    
    ### Token Prediction
    ```php
    // Vulnerable password reset token
    $reset_token = md5(uniqid(rand(), true));
    ```
    Problems:
    - uniqid() uses microsecond timestamp (limited entropy)
    - rand() adds predictable component
    - MD5 doesn't add security, just obfuscates
    - Attackers can predict tokens for other users
    
    ### Cryptographic Key Compromise
    ```php
    // Vulnerable encryption key
    srand(time());
    $key = '';
    for ($i = 0; $i < 32; $i++) {
        $key .= chr(mt_rand(0, 255));
    }
    ```
    Consequences:
    - Encryption keys become predictable
    - All encrypted data can be decrypted
    - Long-term compromise of confidentiality
    
    ## Real-World Impact
    
    ### Historical Vulnerabilities
    - **Debian OpenSSL** (2008): Weak random seeding led to predictable keys
    - **Android Bitcoin wallets** (2013): Weak random numbers caused key reuse
    - **Casino fraud**: Predictable slot machine outcomes
    - **Gaming exploits**: Predictable loot boxes and card shuffles
    
    ### Modern Attack Techniques
    1. **State Recovery**: Analyze outputs to recover generator state
    2. **Seed Prediction**: Guess seeds based on timestamps/PIDs
    3. **Statistical Analysis**: Detect patterns in supposedly random data
    4. **Timing Correlation**: Link randomness to observable events
    
    ## Cryptographically Secure Alternatives
    
    ### PHP 7.0+ Solutions
    ```php
    // Secure integer generation
    $secure_int = random_int($min, $max);
    
    // Secure byte generation
    $secure_bytes = random_bytes($length);
    
    // Secure token generation
    $token = bin2hex(random_bytes(32));
    $url_safe_token = base64url_encode(random_bytes(32));
    ```
    
    ### Legacy PHP Support
    ```php
    // For PHP < 7.0 with OpenSSL
    $secure_bytes = openssl_random_pseudo_bytes($length);
    
    // Check for secure generation
    $bytes = openssl_random_pseudo_bytes(16, $strong);
    if (!$strong) {
        throw new Exception('Unable to generate secure random bytes');
    }
    ```
    
    ### Best Practices
    
    1. **Always use cryptographic functions** for security purposes
    2. **Never seed secure generators** with predictable values
    3. **Generate sufficient entropy** (minimum 128 bits for tokens)
    4. **Use constant-time comparison** for token verification
    5. **Implement proper token expiration** and rotation
    6. **Monitor for prediction attacks** in security logs
    
    ## Defense Strategies
    
    ### Code Review Checklist
    - [ ] No usage of rand() or mt_rand() for security values
    - [ ] All tokens use random_int() or random_bytes()
    - [ ] No predictable seeding of any generators
    - [ ] Sufficient token length (32+ bytes for high security)
    - [ ] Proper token verification with hash_equals()
    - [ ] Token expiration and rotation implemented
    
    ### Testing for Randomness
    ```php
    // Test for predictability
    function testRandomness($generator, $samples = 1000) {
        $values = [];
        for ($i = 0; $i < $samples; $i++) {
            $values[] = $generator();
        }
        
        // Check for patterns, duplicates, statistical biases
        return analyzeRandomness($values);
    }
    ```
    
    Remember: Any security mechanism is only as strong as its weakest component.
    Predictable randomness can compromise the entire security architecture of
    an application, making all other security measures ineffective.
    """
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Php.InsecureRandom.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:min_confidence, :rules]
      
      iex> enhancement = RsolvApi.Security.Patterns.Php.InsecureRandom.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
      
      iex> enhancement = RsolvApi.Security.Patterns.Php.InsecureRandom.ast_enhancement()
      iex> length(enhancement.rules)
      4
  """
  @impl true
  def ast_enhancement do
    %{
      rules: [
        %{
          type: "insecure_functions",
          description: "PHP insecure random number functions",
          functions: [
            "rand",
            "mt_rand",
            "srand", 
            "mt_srand",
            "array_rand",  # Can be predictable if underlying PRNG is weak
            "str_shuffle"  # Uses internal PRNG
          ],
          contexts: [
            "token_generation",
            "session_id_creation", 
            "password_generation",
            "api_key_creation",
            "csrf_token_generation",
            "nonce_generation"
          ]
        },
        %{
          type: "secure_alternatives",
          description: "Cryptographically secure random functions",
          functions: [
            "random_int",
            "random_bytes",
            "openssl_random_pseudo_bytes",
            "mcrypt_create_iv",  # Deprecated but was secure
            "password_hash"      # Includes secure salt generation
          ]
        },
        %{
          type: "context_analysis", 
          description: "Usage context determines security relevance",
          security_sensitive: [
            "session",
            "token", 
            "password",
            "key",
            "secret",
            "nonce",
            "salt",
            "csrf",
            "api_key",
            "auth"
          ],
          non_security: [
            "game",
            "shuffle",
            "demo",
            "test",
            "example",
            "simulation",
            "sample"
          ]
        },
        %{
          type: "variable_analysis",
          description: "Analyze variable names for security context",
          high_risk_variables: [
            "session_id",
            "csrf_token", 
            "api_key",
            "reset_token",
            "auth_token",
            "nonce",
            "salt",
            "password",
            "secret"
          ],
          low_risk_variables: [
            "game_score",
            "demo_data",
            "test_value",
            "sample_number",
            "random_color"
          ]
        }
      ],
      min_confidence: 0.7
    }
  end
end