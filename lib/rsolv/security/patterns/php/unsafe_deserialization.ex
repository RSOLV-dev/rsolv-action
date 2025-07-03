defmodule Rsolv.Security.Patterns.Php.UnsafeDeserialization do
  @moduledoc """
  Pattern for detecting unsafe deserialization vulnerabilities in PHP.
  
  This pattern identifies when the PHP unserialize() function is used with user-controlled
  input, which can lead to PHP Object Injection attacks and Remote Code Execution (RCE).
  
  ## Vulnerability Details
  
  PHP's unserialize() function converts a serialized string back into PHP values and objects.
  When untrusted user input is passed to unserialize(), it creates a dangerous attack vector
  where malicious serialized objects can be injected to achieve arbitrary code execution.
  
  ### Attack Example
  ```php
  // Vulnerable code - user controls the serialized data
  $user_prefs = unserialize($_COOKIE['preferences']);
  
  // Attacker can inject malicious serialized objects:
  // O:8:"EvilClass":1:{s:4:"file";s:10:"/etc/passwd";}
  ```
  
  The attack works by exploiting PHP magic methods like __destruct(), __wakeup(),
  __toString(), and others that are automatically called during object creation
  and destruction, allowing arbitrary code execution.
  """
  
  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "php-unsafe-deserialization",
      name: "Unsafe Deserialization",
      description: "Using unserialize() on user input can lead to RCE",
      type: :deserialization,
      severity: :critical,
      languages: ["php"],
      regex: ~r/unserialize\s*\(\s*[^)]*\$_(GET|POST|REQUEST|COOKIE)/,
      cwe_id: "CWE-502",
      owasp_category: "A08:2021",
      recommendation: "Use JSON instead of serialize/unserialize for user data",
      test_cases: %{
        vulnerable: [
          ~S|$data = unserialize($_COOKIE['data']);|,
          ~S|$obj = unserialize($_POST['object']);|,
          ~S|$result = unserialize($_GET['payload']);|,
          ~S|$user_data = unserialize($_REQUEST['info']);|
        ],
        safe: [
          ~S|$data = json_decode($_COOKIE['data'], true);|,
          ~S|$obj = unserialize($safe_data);|,
          ~S|$obj = unserialize($data, ['allowed_classes' => ['MyClass']]);|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Unsafe deserialization in PHP is a critical security vulnerability that occurs when
      the unserialize() function processes untrusted user input. This vulnerability enables
      PHP Object Injection attacks, where malicious serialized objects can be crafted to
      execute arbitrary code during the deserialization process.
      
      The core issue stems from PHP's object lifecycle management and magic methods.
      When unserialize() reconstructs objects from serialized data, it automatically
      triggers various magic methods (__construct, __destruct, __wakeup, __toString, etc.)
      during object creation, property access, and destruction. Attackers can exploit
      these automatic method invocations by crafting malicious serialized payloads.
      
      ### The Deserialization Process
      
      PHP serialization creates a string representation of objects that preserves:
      - Object class name and properties
      - Property values and types
      - Object relationships and references
      - Magic method triggers during reconstruction
      
      When unserialize() processes this data, it:
      1. Creates instances of the specified classes
      2. Sets object properties to stored values
      3. Calls __wakeup() if defined
      4. Eventually calls __destruct() when objects are garbage collected
      
      ### Attack Mechanics
      
      Successful exploitation typically requires:
      1. **Gadget Classes**: Existing classes with exploitable magic methods
      2. **Property Control**: Ability to control object property values
      3. **Chain Construction**: Linking gadgets to achieve desired effects
      4. **Payload Delivery**: Injecting malicious serialized data via user input
      
      Common gadget patterns include:
      - File operations in __destruct() methods
      - System commands in __toString() methods
      - Include/require statements in property setters
      - Database operations with controlled parameters
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-502",
          title: "Deserialization of Untrusted Data",
          url: "https://cwe.mitre.org/data/definitions/502.html"
        },
        %{
          type: :owasp,
          id: "A08:2021",
          title: "OWASP Top 10 2021 - A08 Software and Data Integrity Failures",
          url: "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
        },
        %{
          type: :owasp,
          id: "php_object_injection",
          title: "OWASP PHP Object Injection",
          url: "https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection"
        },
        %{
          type: :research,
          id: "sjoerd_unserialize_rce",
          title: "Remote code execution through unsafe unserialize in PHP",
          url: "https://www.sjoerdlangkemper.nl/2021/04/04/remote-code-execution-through-unsafe-unserialize/"
        },
        %{
          type: :research,
          id: "portswigger_deserialization",
          title: "Exploiting insecure deserialization vulnerabilities",
          url: "https://portswigger.net/web-security/deserialization/exploiting"
        }
      ],
      attack_vectors: [
        "Object injection via crafted serialize() payloads in cookies",
        "RCE through __destruct() magic method exploitation",
        "File inclusion via __autoload() and property manipulation",
        "SQL injection through __toString() method chaining",
        "Local file inclusion via path manipulation in destructors",
        "System command execution via exec() calls in magic methods",
        "Memory corruption through property type confusion",
        "Authentication bypass via session object manipulation"
      ],
      real_world_impact: [
        "Complete server compromise through remote code execution",
        "Data exfiltration via file read operations in destructors",
        "Privilege escalation through configuration object manipulation",
        "Database compromise via SQL injection in magic methods",
        "Session hijacking through user object property modification",
        "File system manipulation including arbitrary file deletion",
        "Denial of service via resource exhaustion in object construction",
        "Web application takeover through admin object injection"
      ],
      cve_examples: [
        %{
          id: "CVE-2024-54135",
          description: "ClipBucket PHP Deserialization vulnerability",
          severity: "critical",
          cvss: 9.8,
          note: "Remote code execution via unserialize() in upload functionality"
        },
        %{
          id: "CVE-2023-46817",
          description: "Auth0 PHP SDK insecure deserialization of cookie data",
          severity: "high",
          cvss: 8.1,
          note: "Malicious serialized data in cookies leading to RCE"
        },
        %{
          id: "CVE-2023-30534",
          description: "Cacti insecure deserialization prior to version 1.2.25",
          severity: "critical",
          cvss: 9.8,
          note: "Multiple instances of unsafe unserialize() in lib/functions.php"
        },
        %{
          id: "CVE-2019-17358",
          description: "Cacti multiple unsafe deserialization instances",
          severity: "high",
          cvss: 8.8,
          note: "lib/functions.php unsafe deserialization of user-controlled data"
        },
        %{
          id: "CVE-2025-49113",
          description: "Roundcube Webmail PHP deserialization vulnerability",
          severity: "critical",
          cvss: 9.9,
          note: "Unsafe PHP object deserialization in webmail platform"
        }
      ],
      detection_notes: """
      This pattern detects unsafe deserialization by identifying:
      - Direct calls to unserialize() with user input variables ($_GET, $_POST, $_REQUEST, $_COOKIE)
      - Function patterns that process user-controlled serialized data
      - Common injection points where serialized data enters the application
      
      The regex specifically looks for:
      - unserialize function calls with various whitespace patterns
      - Immediate access to superglobal variables containing user input
      - Common parameter names used for serialized data transport
      
      False positives may occur when:
      - unserialize() is used with validated or internal data
      - Proper input validation is performed before deserialization
      - allowed_classes option is used to restrict object types
      """,
      safe_alternatives: [
        "Use json_decode() instead of unserialize() for data exchange",
        "If unserialize() is necessary, use allowed_classes option to restrict types",
        "Validate and sanitize all input before any deserialization",
        "Use message authentication codes (MAC) to verify data integrity",
        "Implement custom serialization formats with strict validation",
        "Use array structures instead of objects for data transport",
        "Apply cryptographic signatures to verify serialized data authenticity",
        "Use specialized libraries like msgpack for safer binary serialization"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing that base64 encoding adds security to serialized data",
          "Using unserialize() with input validation that only checks data format",
          "Assuming that serialized data from 'trusted' sources is safe",
          "Implementing custom __wakeup() methods without security considerations",
          "Using unserialize() in session handlers without proper validation",
          "Storing serialized objects in databases accessible to users"
        ],
        secure_patterns: [
          "json_decode($_POST['data'], true) for array data structures",
          "unserialize($data, ['allowed_classes' => ['SafeClass']]) for restricted objects",
          "hash_hmac('sha256', $data, $secret) for data integrity verification",
          "Custom validation functions before any deserialization attempts",
          "Whitelist-based approach for acceptable data structures"
        ],
        php_version_notes: [
          "PHP 7.0+ introduced allowed_classes option for unserialize()",
          "PHP 5.6 and earlier have no protection mechanisms for unserialize()",
          "Modern PHP versions still vulnerable without proper allowed_classes usage",
          "Serialization format changed in PHP 7.4 but vulnerabilities remain",
          "PHP 8.x maintains backward compatibility with vulnerable patterns"
        ],
        framework_considerations: [
          "Laravel: Uses secure serialization by default but custom code vulnerable",
          "Symfony: Provides security components but unserialize() still dangerous",
          "WordPress: Multiple plugins vulnerable to object injection attacks",
          "Drupal: Core protections exist but contributed modules often vulnerable",
          "CodeIgniter: Session handling can be vulnerable with certain configurations"
        ]
      }
    }
  end
  
  @doc """
  Returns test cases for the pattern.
  
  ## Examples
  
      iex> test_cases = Rsolv.Security.Patterns.Php.UnsafeDeserialization.test_cases()
      iex> length(test_cases.positive) > 0
      true
      
      iex> test_cases = Rsolv.Security.Patterns.Php.UnsafeDeserialization.test_cases()
      iex> length(test_cases.negative) > 0
      true
      
      iex> pattern = Rsolv.Security.Patterns.Php.UnsafeDeserialization.pattern()
      iex> pattern.id
      "php-unsafe-deserialization"
  """
  def test_cases do
    %{
      positive: [
        %{
          code: ~S|$data = unserialize($_COOKIE['data']);|,
          description: "Basic unserialize with cookie data"
        },
        %{
          code: ~S|$obj = unserialize($_POST['object']);|,
          description: "Object deserialization from POST data"
        },
        %{
          code: ~S|$result = unserialize($_GET['payload']);|,
          description: "Deserialization from GET parameter"
        },
        %{
          code: ~S|$user_data = unserialize($_REQUEST['info']);|,
          description: "REQUEST superglobal deserialization"
        },
        %{
          code: ~S|unserialize($_COOKIE['session']);|,
          description: "Direct unserialize call with cookie"
        },
        %{
          code: ~S|$config = unserialize( $_POST['config'] );|,
          description: "Unserialize with whitespace"
        },
        %{
          code: ~S|if (isset($_GET['data'])) { $obj = unserialize($_GET['data']); }|,
          description: "Conditional deserialization"
        },
        %{
          code: ~S|return unserialize($_COOKIE['state']);|,
          description: "Return statement with unserialize"
        },
        %{
          code: ~S|$cache = unserialize($_REQUEST['cache']);|,
          description: "Direct REQUEST superglobal usage"
        }
      ],
      negative: [
        %{
          code: ~S|$data = json_decode($_COOKIE['data'], true);|,
          description: "Safe JSON decoding"
        },
        %{
          code: ~S|$obj = unserialize($safe_data);|,
          description: "Unserialize with internal data"
        },
        %{
          code: ~S|$obj = unserialize($data, ['allowed_classes' => ['MyClass']]);|,
          description: "Restricted unserialize with allowed classes"
        },
        %{
          code: ~S|$validated = filter_var($_POST['data'], FILTER_SANITIZE_STRING); $obj = unserialize($validated);|,
          description: "Validated input before unserialize"
        },
        %{
          code: ~S|function unserialize_safe($data) { return json_decode($data, true); }|,
          description: "Custom function name containing 'unserialize'"
        },
        %{
          code: ~S|$result = unserialize($internal_cache);|,
          description: "Internal variable deserialization"
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
        "Session Management" => ~S"""
        // Session data storage - VULNERABLE
        session_start();
        
        // Store user preferences in session
        if ($_POST['save_prefs']) {
            $_SESSION['user_prefs'] = serialize($_POST['preferences']);
        }
        
        // Load user preferences - DANGEROUS
        if (isset($_COOKIE['backup_prefs'])) {
            $prefs = unserialize($_COOKIE['backup_prefs']);
            foreach ($prefs as $key => $value) {
                $_SESSION[$key] = $value;
            }
        }
        
        // Attacker can inject malicious objects via cookie
        """,
        "Configuration Loading" => ~S"""
        // Application configuration - VULNERABLE
        class Config {
            public $debug_mode = false;
            public $log_file = '/var/log/app.log';
            
            public function __destruct() {
                if ($this->debug_mode) {
                    // DANGEROUS: File operations in destructor
                    file_put_contents($this->log_file, "Debug mode enabled\n", FILE_APPEND);
                }
            }
        }
        
        // Load configuration from user input
        if (isset($_POST['config'])) {
            $config = unserialize($_POST['config']);
            $GLOBALS['app_config'] = $config;
        }
        
        // Attacker controls log_file path and debug_mode flag
        """,
        "Cache Management" => ~S"""
        // Cache system - VULNERABLE
        class CacheEntry {
            public $key;
            public $data;
            public $file_path;
            
            public function __toString() {
                // DANGEROUS: File inclusion in magic method
                if (file_exists($this->file_path)) {
                    return file_get_contents($this->file_path);
                }
                return $this->data;
            }
        }
        
        // Restore cache from user input
        if (isset($_GET['restore_cache'])) {
            $cache_data = base64_decode($_GET['restore_cache']);
            $cache_entry = unserialize($cache_data);
            echo "Cache restored: " . $cache_entry;
        }
        
        // Attacker can read arbitrary files via file_path property
        """,
        "User Profile" => ~S"""
        // User profile management - VULNERABLE
        class UserProfile {
            public $username;
            public $avatar_path;
            public $settings;
            
            public function __wakeup() {
                // DANGEROUS: Automatic file operations
                if ($this->avatar_path && !file_exists($this->avatar_path)) {
                    copy('/default/avatar.png', $this->avatar_path);
                }
            }
        }
        
        // Import user profile from backup
        if (isset($_FILES['profile_backup'])) {
            $backup_data = file_get_contents($_FILES['profile_backup']['tmp_name']);
            $profile = unserialize($backup_data);
            $_SESSION['user_profile'] = $profile;
        }
        
        // Attacker can trigger file operations via avatar_path
        """
      },
      fixed: %{
        "Using JSON instead" => ~S"""
        // Session data storage - SECURE
        session_start();
        
        // Store user preferences as JSON
        if ($_POST['save_prefs']) {
            $prefs = [
                'theme' => filter_var($_POST['theme'], FILTER_SANITIZE_STRING),
                'language' => filter_var($_POST['language'], FILTER_SANITIZE_STRING),
                'timezone' => filter_var($_POST['timezone'], FILTER_SANITIZE_STRING)
            ];
            $_SESSION['user_prefs'] = json_encode($prefs);
        }
        
        // Load user preferences safely
        if (isset($_COOKIE['backup_prefs'])) {
            $prefs_json = filter_var($_COOKIE['backup_prefs'], FILTER_SANITIZE_STRING);
            $prefs = json_decode($prefs_json, true);
            
            if (is_array($prefs)) {
                foreach ($prefs as $key => $value) {
                    if (in_array($key, ['theme', 'language', 'timezone'])) {
                        $_SESSION[$key] = $value;
                    }
                }
            }
        }
        """,
        "Safe unserialize with allowed_classes" => ~S"""
        // Configuration loading - SECURE
        class SafeConfig {
            public $theme = 'default';
            public $language = 'en';
            
            // No dangerous magic methods
            public function validate() {
                $allowed_themes = ['default', 'dark', 'light'];
                $allowed_languages = ['en', 'es', 'fr', 'de'];
                
                if (!in_array($this->theme, $allowed_themes)) {
                    $this->theme = 'default';
                }
                
                if (!in_array($this->language, $allowed_languages)) {
                    $this->language = 'en';
                }
            }
        }
        
        // Only allow specific safe classes
        if (isset($_POST['config'])) {
            $config = unserialize($_POST['config'], [
                'allowed_classes' => ['SafeConfig']
            ]);
            
            if ($config instanceof SafeConfig) {
                $config->validate();
                $GLOBALS['app_config'] = $config;
            }
        }
        """,
        "Input validation and MAC verification" => ~S"""
        // Cache system - SECURE
        function createSecureCache($key, $data) {
            $cache_array = [
                'key' => $key,
                'data' => $data,
                'timestamp' => time()
            ];
            
            $serialized = json_encode($cache_array);
            $mac = hash_hmac('sha256', $serialized, SECRET_KEY);
            
            return base64_encode($serialized . '.' . $mac);
        }
        
        function loadSecureCache($cache_token) {
            $decoded = base64_decode($cache_token);
            $parts = explode('.', $decoded, 2);
            
            if (count($parts) !== 2) {
                return false;
            }
            
            [$data, $mac] = $parts;
            $expected_mac = hash_hmac('sha256', $data, SECRET_KEY);
            
            if (!hash_equals($expected_mac, $mac)) {
                return false; // MAC verification failed
            }
            
            $cache_array = json_decode($data, true);
            if (!is_array($cache_array)) {
                return false;
            }
            
            return $cache_array;
        }
        
        // Secure cache restoration
        if (isset($_GET['restore_cache'])) {
            $cache_data = loadSecureCache($_GET['restore_cache']);
            if ($cache_data) {
                echo "Cache restored safely: " . htmlspecialchars($cache_data['data']);
            }
        }
        """,
        "Custom safe serialization" => ~S"""
        // User profile management - SECURE
        class SecureUserProfile {
            private $allowed_fields = ['username', 'email', 'theme', 'language'];
            private $data = [];
            
            public function setField($field, $value) {
                if (in_array($field, $this->allowed_fields)) {
                    $this->data[$field] = filter_var($value, FILTER_SANITIZE_STRING);
                }
            }
            
            public function getField($field) {
                return $this->data[$field] ?? null;
            }
            
            public function toArray() {
                return $this->data;
            }
            
            public static function fromArray($data) {
                $profile = new self();
                if (is_array($data)) {
                    foreach ($data as $field => $value) {
                        $profile->setField($field, $value);
                    }
                }
                return $profile;
            }
        }
        
        // Import user profile securely
        if (isset($_FILES['profile_backup'])) {
            $backup_json = file_get_contents($_FILES['profile_backup']['tmp_name']);
            $profile_data = json_decode($backup_json, true);
            
            if (is_array($profile_data)) {
                $profile = SecureUserProfile::fromArray($profile_data);
                $_SESSION['user_profile'] = $profile->toArray();
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
    Unsafe deserialization is one of the most critical vulnerabilities in PHP applications,
    capable of leading to complete server compromise through remote code execution. This
    vulnerability occurs when the unserialize() function processes untrusted user input,
    allowing attackers to inject malicious PHP objects that execute arbitrary code through
    PHP object injection attacks.
    
    ## Understanding PHP Object Injection
    
    ### The Serialization Process
    
    PHP serialization converts complex data structures into string representations:
    
    ```php
    $user = new User();
    $user->name = "John";
    $user->role = "admin";
    
    $serialized = serialize($user);
    // O:4:"User":2:{s:4:"name";s:4:"John";s:4:"role";s:5:"admin";}
    ```
    
    The serialized format contains:
    - **O:4:"User"**: Object of class "User" with 4 characters in name
    - **:2**: Object has 2 properties
    - **{...}**: Property definitions with names and values
    
    ### The Vulnerability Mechanism
    
    When unserialize() processes malicious data, it can:
    1. **Instantiate arbitrary classes** available in the application
    2. **Set object properties** to attacker-controlled values
    3. **Trigger magic methods** automatically during object lifecycle
    4. **Execute code** through method chaining and property manipulation
    
    ### Magic Method Exploitation
    
    PHP's magic methods provide numerous exploitation vectors:
    
    #### __destruct() - Destructor Method
    Called when objects are destroyed or script ends:
    ```php
    class FileLogger {
        public $logFile = '/var/log/app.log';
        
        public function __destruct() {
            file_put_contents($this->logFile, "Session ended\n", FILE_APPEND);
        }
    }
    
    // Attacker payload: O:10:"FileLogger":1:{s:7:"logFile";s:17:"/var/www/shell.php";}
    // Result: Creates web shell at controlled location
    ```
    
    #### __wakeup() - Called After Unserialization
    Executed immediately when object is unserialized:
    ```php
    class ConfigLoader {
        public $configFile = 'config.php';
        
        public function __wakeup() {
            include $this->configFile;
        }
    }
    
    // Attacker can trigger arbitrary file inclusion
    ```
    
    #### __toString() - String Conversion
    Called when object is used as string:
    ```php
    class TemplateEngine {
        public $template = '';
        
        public function __toString() {
            return eval("return \"$this->template\";");
        }
    }
    
    // Direct code execution when object is echoed
    ```
    
    ## Advanced Attack Techniques
    
    ### Property-Oriented Programming (POP) Chains
    
    Complex attacks chain multiple objects together:
    
    ```php
    // Step 1: Object with file write in destructor
    class Logger {
        public $file;
        public $data;
        
        public function __destruct() {
            file_put_contents($this->file, $this->data);
        }
    }
    
    // Step 2: Object that triggers string conversion
    class Template {
        public $content;
        
        public function __toString() {
            return $this->content->process();
        }
    }
    
    // Step 3: Object with method call
    class Processor {
        public $logger;
        
        public function process() {
            return (string) $this->logger;
        }
    }
    
    // Chain: Processor -> Template -> Logger -> file_put_contents()
    ```
    
    ### Gadget Discovery
    
    Attackers search for "gadgets" - classes with exploitable magic methods:
    - **File operations**: read, write, delete, include
    - **Network requests**: HTTP calls, email sending
    - **Command execution**: system(), exec(), shell_exec()
    - **Database operations**: SQL queries, data modification
    
    ## Real-World Attack Scenarios
    
    ### Session Hijacking
    ```php
    // Vulnerable session restoration
    if (isset($_COOKIE['session_backup'])) {
        $_SESSION = unserialize($_COOKIE['session_backup']);
    }
    
    // Attacker injects admin session:
    // a:1:{s:4:"role";s:5:"admin";}
    ```
    
    ### Configuration Manipulation
    ```php
    // Vulnerable config loading
    $config = unserialize($_POST['settings']);
    
    // Attacker overwrites critical settings:
    // O:6:"Config":1:{s:8:"database";s:20:"mysql://evil.com/db";}
    ```
    
    ### File System Attacks
    ```php
    // Vulnerable cache system
    class CacheEntry {
        public $file;
        
        public function __destruct() {
            unlink($this->file); // Delete file
        }
    }
    
    // Attacker deletes critical files:
    // O:10:"CacheEntry":1:{s:4:"file";s:15:"/etc/passwd";}
    ```
    
    ## Detection and Prevention
    
    ### Immediate Actions
    1. **Replace unserialize() with json_decode()** for data exchange
    2. **Use allowed_classes parameter** if unserialize() is necessary
    3. **Validate all input** before any deserialization
    4. **Implement data integrity checks** using MAC or signatures
    
    ### Secure Alternatives
    ```php
    // JSON instead of serialization
    $data = json_decode($_POST['data'], true);
    
    // Restricted unserialize
    $obj = unserialize($data, ['allowed_classes' => ['SafeClass']]);
    
    // Integrity verification
    $mac = hash_hmac('sha256', $data, $secret_key);
    if (hash_equals($expected_mac, $mac)) {
        $obj = unserialize($data);
    }
    ```
    
    ### Code Review Checklist
    - [ ] No unserialize() calls with user input
    - [ ] All serialization uses JSON or other safe formats
    - [ ] Magic methods (__destruct, __wakeup, etc.) reviewed for safety
    - [ ] Input validation implemented before any deserialization
    - [ ] Data integrity verification in place for serialized data
    - [ ] Session handling doesn't use unserialize() with user data
    
    Remember: Unsafe deserialization can lead to complete application compromise.
    The best defense is avoiding unserialize() with user input entirely.
    """
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual vulnerabilities and false positives
  by analyzing the context of unserialize() usage and checking for safety measures.
  
  ## Examples
  
      iex> enhancement = Rsolv.Security.Patterns.Php.UnsafeDeserialization.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Php.UnsafeDeserialization.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
      
      iex> enhancement = Rsolv.Security.Patterns.Php.UnsafeDeserialization.ast_enhancement()
      iex> length(enhancement.ast_rules)
      4
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: [
        %{
          type: "insecure_functions",
          description: "PHP deserialization functions with security implications",
          functions: [
            "unserialize",
            "wakeup",      # Magic method that can be exploited
            "destruct"     # Destructor method exploitation
          ],
          contexts: [
            "user_input_processing",
            "session_handling",
            "cache_restoration",
            "configuration_loading",
            "data_import"
          ]
        },
        %{
          type: "secure_alternatives",
          description: "Safe deserialization and data processing functions",
          functions: [
            "json_decode",
            "json_encode",
            "filter_var",
            "filter_input",
            "hash_hmac",
            "hash_equals"
          ]
        },
        %{
          type: "context_analysis",
          description: "Analyze usage context to determine risk level",
          high_risk_patterns: [
            "unserialize with $_GET, $_POST, $_REQUEST, $_COOKIE",
            "unserialize with file_get_contents and user paths",
            "unserialize in session handlers",
            "unserialize with base64_decode user input",
            "unserialize without allowed_classes restriction"
          ],
          mitigation_indicators: [
            "allowed_classes parameter present",
            "input validation before unserialize",
            "MAC verification with hash_hmac",
            "whitelist validation of input",
            "try/catch error handling around unserialize"
          ],
          false_positive_patterns: [
            "unserialize with hardcoded strings",
            "unserialize with internal variables only",
            "unserialize in unit tests",
            "commented unserialize code",
            "unserialize with strict validation"
          ]
        },
        %{
          type: "user_input_sources",
          description: "Identify sources of user-controlled data",
          dangerous_sources: [
            "$_GET",
            "$_POST", 
            "$_REQUEST",
            "$_COOKIE",
            "$_FILES",
            "file_get_contents with user paths",
            "stream_get_contents with user streams",
            "database results from user queries"
          ],
          safe_sources: [
            "hardcoded strings",
            "configuration constants",
            "internal application variables",
            "validated and sanitized inputs",
            "MAC-verified data"
          ]
        }
      ],
      min_confidence: 0.8
    }
  end
end
