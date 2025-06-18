defmodule RsolvApi.Security.Patterns.Php.PathTraversal do
  @moduledoc """
  Pattern for detecting path traversal vulnerabilities in PHP.
  
  This pattern identifies when PHP file access functions like file_get_contents(),
  fopen(), include, require, or readfile() are used with user-controlled input
  without proper validation, potentially allowing attackers to access files
  outside the intended directory structure.
  
  ## Vulnerability Details
  
  Path traversal (also known as directory traversal) is a security vulnerability
  that allows attackers to access files and directories that are stored outside
  the web application's intended directory. This occurs when user input is used
  to construct file paths without proper validation or sanitization.
  
  ### Attack Example
  ```php
  // Vulnerable code - user controls the file path
  $file = $_GET['file'];
  $content = file_get_contents('./uploads/' . $file);
  
  // Attacker can use: ?file=../../etc/passwd
  // Resulting path: ./uploads/../../etc/passwd
  // Which resolves to: /etc/passwd
  ```
  
  The attack exploits relative path sequences like "../" (dot-dot-slash) to
  navigate up the directory structure and access sensitive files outside
  the application's intended scope.
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "php-path-traversal",
      name: "Path Traversal",
      description: "File path manipulation vulnerability",
      type: :path_traversal,
      severity: :high,
      languages: ["php"],
      regex: ~r/(file_get_contents|fopen|readfile)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)|(include|include_once|require|require_once)\s*\(?[^;]*\$_(GET|POST|REQUEST|COOKIE)/,
      default_tier: :ai,
      cwe_id: "CWE-22",
      owasp_category: "A01:2021",
      recommendation: "Validate and sanitize file paths, use basename() or realpath()",
      test_cases: %{
        vulnerable: [
          ~S|$content = file_get_contents('uploads/' . $_GET['file']);|,
          ~S|include('./pages/' . $_GET['page']);|,
          ~S|$handle = fopen($_POST['filename'], 'r');|,
          ~S|require('./modules/' . $_REQUEST['module']);|,
          ~S|readfile('documents/' . $_COOKIE['doc']);|
        ],
        safe: [
          ~S|$content = file_get_contents('config.php');|,
          ~S|include './templates/header.php';|,
          ~S|$handle = fopen($validated_path, 'r');|,
          ~S|$file = basename($_GET['file']); $content = file_get_contents('./uploads/' . $file);|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Path traversal is a critical web security vulnerability that allows attackers to access
      files and directories outside the intended application directory structure. This vulnerability
      occurs when user input is used to construct file paths without proper validation, enabling
      attackers to use relative path sequences like "../" to navigate the file system and access
      sensitive files such as configuration files, password files, or application source code.
      
      In PHP applications, path traversal vulnerabilities commonly arise when file access functions
      like file_get_contents(), fopen(), include, require, or readfile() process user-controlled
      input without adequate path validation. These functions treat user input as legitimate file
      paths, making them susceptible to directory traversal attacks.
      
      ### The Attack Mechanism
      
      Path traversal attacks exploit the file system's directory navigation features:
      1. **Relative Path Sequences**: Use "../" to move up directory levels
      2. **Absolute Paths**: Directly specify full paths to system files
      3. **URL Encoding**: Encode traversal sequences to bypass basic filters
      4. **Double Encoding**: Use multiple encoding layers to evade detection
      
      ### Common Attack Vectors
      
      #### Basic Directory Traversal
      ```
      GET /download.php?file=../../../etc/passwd
      ```
      
      #### URL-Encoded Traversal
      ```
      GET /download.php?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
      ```
      
      #### Double-Encoded Traversal
      ```
      GET /download.php?file=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
      ```
      
      #### Null Byte Injection (PHP < 5.3.4)
      ```
      GET /download.php?file=../../../etc/passwd%00.txt
      ```
      
      ### Impact and Consequences
      
      Successful path traversal attacks can lead to:
      - **Configuration File Disclosure**: Access to database credentials, API keys
      - **Source Code Exposure**: Revelation of application logic and vulnerabilities
      - **System File Access**: Reading /etc/passwd, shadow files, log files
      - **Arbitrary File Read**: Access to any readable file on the server
      - **Information Disclosure**: Exposure of sensitive business data
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-22",
          title: "Improper Limitation of a Pathname to a Restricted Directory",
          url: "https://cwe.mitre.org/data/definitions/22.html"
        },
        %{
          type: :owasp,
          id: "A01:2021",
          title: "OWASP Top 10 2021 - A01 Broken Access Control",
          url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
        },
        %{
          type: :owasp,
          id: "path_traversal",
          title: "OWASP Path Traversal",
          url: "https://owasp.org/www-community/attacks/Path_Traversal"
        },
        %{
          type: :owasp,
          id: "testing_directory_traversal",
          title: "OWASP Testing Guide - Directory Traversal",
          url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include"
        },
        %{
          type: :research,
          id: "acunetix_php_security",
          title: "PHP Security: Directory Traversal & Code Injection",
          url: "https://www.acunetix.com/websitesecurity/php-security-2/"
        }
      ],
      attack_vectors: [
        "Basic directory traversal using ../ sequences to access parent directories",
        "Absolute path injection to directly access system files like /etc/passwd",
        "URL encoding of traversal sequences to bypass basic input filters",
        "Double URL encoding to evade more sophisticated filtering mechanisms",
        "Null byte injection (older PHP versions) to truncate file extensions",
        "Mixed case and alternate representations of path separators",
        "Unicode encoding variations to bypass character-based filters",
        "Combining multiple encoding techniques to defeat layered defenses"
      ],
      real_world_impact: [
        "Complete server configuration disclosure including database credentials",
        "Application source code exposure revealing business logic and vulnerabilities",
        "System user information disclosure through /etc/passwd and /etc/shadow access",
        "Log file access revealing sensitive user activities and system information",
        "SSH key and certificate file disclosure enabling further lateral movement",
        "Application configuration file access exposing API keys and secrets",
        "Backup file discovery containing sensitive historical data",
        "Operating system and software version disclosure aiding further attacks"
      ],
      cve_examples: [
        %{
          id: "CVE-2024-7924",
          description: "ZZCMS list.php path traversal vulnerability via skin parameter",
          severity: "critical",
          cvss: 9.8,
          note: "Remote path traversal in /I/list.php allowing arbitrary file access"
        },
        %{
          id: "CVE-2024-7927",
          description: "ZZCMS class.php path traversal via skin[] parameter",
          severity: "critical",
          cvss: 9.1,
          note: "Array-based path traversal attack in admin interface"
        },
        %{
          id: "CVE-2024-42007",
          description: "php-spx path traversal via SPX_UI_URI parameter",
          severity: "high",
          cvss: 7.5,
          note: "Unauthenticated arbitrary file read in PHP profiling extension"
        },
        %{
          id: "CVE-2024-7926",
          description: "ZZCMS about_edit.php path traversal vulnerability",
          severity: "critical",
          cvss: 9.0,
          note: "Admin interface path traversal in content management system"
        },
        %{
          id: "CVE-2023-34967",
          description: "Path traversal in multiple WordPress plugins",
          severity: "high",
          cvss: 8.5,
          note: "File inclusion vulnerability affecting thousands of WordPress sites"
        }
      ],
      detection_notes: """
      This pattern detects path traversal vulnerabilities by identifying:
      - PHP file access functions that commonly process file paths
      - Direct usage of superglobal variables ($_GET, $_POST, $_REQUEST, $_COOKIE) in file paths
      - Function calls that combine user input with file system operations
      - Common patterns where user input is concatenated with base paths
      
      The regex specifically looks for:
      - file_get_contents(), fopen(), readfile() - file reading functions
      - include, include_once, require, require_once - file inclusion functions
      - Direct access to user input variables in function parameters
      - Various whitespace and formatting patterns around function calls
      
      False positives may occur when:
      - File operations use properly validated input variables
      - Hardcoded file paths are used without user input
      - Input validation functions like basename() or realpath() are applied
      - Allowlist-based validation restricts acceptable file paths
      """,
      safe_alternatives: [
        "Use basename() to strip directory paths: basename($_GET['file'])",
        "Validate input against an allowlist of acceptable files",
        "Use realpath() to resolve and validate the final path",
        "Implement proper input sanitization removing ../ sequences",
        "Use file_exists() to verify files exist in expected locations",
        "Create a mapping system instead of direct file path construction",
        "Implement chroot jail or similar containment mechanisms",
        "Use relative paths within a secured directory structure"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing that basic string replacement of ../ is sufficient protection",
          "Using only basename() without validating the directory component",
          "Assuming that URL decoding prevents all traversal attempts",
          "Implementing blacklist-based filtering instead of allowlist validation",
          "Trusting user input for any part of file path construction",
          "Not considering null byte injection in older PHP versions"
        ],
        secure_patterns: [
          "basename($_GET['file']) to extract filename only",
          "realpath($path) to resolve and validate full paths",
          "in_array($file, $allowed_files) for allowlist validation",
          "preg_match('/^[a-zA-Z0-9._-]+$/', $file) for character validation",
          "str_replace('..', '', $input) combined with additional validation"
        ],
        php_version_notes: [
          "PHP < 5.3.4: Vulnerable to null byte injection attacks",
          "PHP 5.3.4+: Null byte handling improved but other vectors remain",
          "PHP 7.0+: Enhanced security functions available",
          "PHP 8.0+: Stricter type checking helps prevent some attacks",
          "All versions: Require explicit validation for path traversal prevention"
        ],
        framework_considerations: [
          "Laravel: Route model binding can prevent some path traversal",
          "Symfony: Security component provides path validation utilities",
          "WordPress: wp_safe_redirect() and related functions provide protection",
          "Drupal: File API includes built-in path validation",
          "CodeIgniter: Input class provides some filtering capabilities"
        ]
      }
    }
  end
  
  @doc """
  Returns test cases for the pattern.
  
  ## Examples
  
      iex> test_cases = RsolvApi.Security.Patterns.Php.PathTraversal.test_cases()
      iex> length(test_cases.positive) > 0
      true
      
      iex> test_cases = RsolvApi.Security.Patterns.Php.PathTraversal.test_cases()
      iex> length(test_cases.negative) > 0
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Php.PathTraversal.pattern()
      iex> pattern.id
      "php-path-traversal"
  """
  def test_cases do
    %{
      positive: [
        %{
          code: ~S|$content = file_get_contents('uploads/' . $_GET['file']);|,
          description: "file_get_contents with GET parameter"
        },
        %{
          code: ~S|include('./pages/' . $_GET['page']);|,
          description: "include with user-controlled path"
        },
        %{
          code: ~S|$handle = fopen($_POST['filename'], 'r');|,
          description: "fopen with POST parameter"
        },
        %{
          code: ~S|require('./modules/' . $_REQUEST['module']);|,
          description: "require with REQUEST parameter"
        },
        %{
          code: ~S|readfile('documents/' . $_COOKIE['doc']);|,
          description: "readfile with cookie parameter"
        },
        %{
          code: ~S|include_once('/templates/' . $_GET['template'] . '.php');|,
          description: "include_once with path construction"
        },
        %{
          code: ~S|require_once($_POST['script']);|,
          description: "require_once with direct user input"
        },
        %{
          code: ~S|$data = file_get_contents('/var/log/' . $_REQUEST['logfile']);|,
          description: "file access in system directories"
        },
        %{
          code: ~S|$fp = fopen('./config/' . $_COOKIE['env'] . '.conf', 'r');|,
          description: "Configuration file access with user input"
        },
        %{
          code: ~S|readfile('./downloads/' . $_GET['filename']);|,
          description: "File download with user-controlled filename"
        }
      ],
      negative: [
        %{
          code: ~S|$content = file_get_contents('config.php');|,
          description: "Hardcoded file path"
        },
        %{
          code: ~S|include './templates/header.php';|,
          description: "Static file inclusion"
        },
        %{
          code: ~S|$handle = fopen($validated_path, 'r');|,
          description: "Pre-validated file path"
        },
        %{
          code: ~S|$file = basename($_GET['file']); $content = file_get_contents('./uploads/' . $file);|,
          description: "basename() validation applied"
        },
        %{
          code: ~S|if (in_array($_GET['page'], $allowed_pages)) { include('./pages/' . $_GET['page']); }|,
          description: "Allowlist validation"
        },
        %{
          code: ~S|$realpath = realpath('./uploads/' . $_GET['file']); if (strpos($realpath, '/uploads/') === 0) { readfile($realpath); }|,
          description: "realpath() with directory validation"
        },
        %{
          code: ~S|function file_get_contents_safe($file) { return file_get_contents($file); }|,
          description: "Function name containing file operation"
        },
        %{
          code: ~S|$data = json_decode($_POST['data'], true); $content = file_get_contents($data['filename']);|,
          description: "Indirect access through data structure"
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
        "File Download System" => ~S"""
        // File download - VULNERABLE
        if (isset($_GET['file'])) {
            $filename = $_GET['file'];
            $filepath = './downloads/' . $filename;
            
            if (file_exists($filepath)) {
                header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename="' . $filename . '"');
                readfile($filepath);
            } else {
                echo "File not found";
            }
        }
        
        // Attack: ?file=../../../etc/passwd
        // Results in: ./downloads/../../../etc/passwd -> /etc/passwd
        """,
        "Template Loading" => ~S"""
        // Template system - VULNERABLE
        $template = $_GET['template'] ?? 'default';
        $theme = $_GET['theme'] ?? 'standard';
        
        // Load template file
        $template_path = './themes/' . $theme . '/templates/' . $template . '.php';
        
        if (file_exists($template_path)) {
            include $template_path;
        } else {
            include './themes/standard/templates/error.php';
        }
        
        // Attack: ?theme=../../../etc&template=passwd
        // Results in: ./themes/../../../etc/templates/passwd.php -> /etc/passwd.php
        """,
        "Log Viewer" => ~S"""
        // Log viewing system - VULNERABLE
        function viewLog() {
            $logfile = $_POST['logfile'] ?? 'application.log';
            $log_path = '/var/log/myapp/' . $logfile;
            
            // Display log contents
            if (file_exists($log_path)) {
                $contents = file_get_contents($log_path);
                echo '<pre>' . htmlspecialchars($contents) . '</pre>';
            }
        }
        
        // Attack: logfile=../../../etc/passwd
        // Results in: /var/log/myapp/../../../etc/passwd -> /etc/passwd
        """,
        "Configuration Manager" => ~S"""
        // Configuration management - VULNERABLE
        class ConfigManager {
            private $config_dir = './config/';
            
            public function loadConfig($env) {
                $config_file = $this->config_dir . $env . '.php';
                
                if (file_exists($config_file)) {
                    return include $config_file;
                }
                
                throw new Exception('Configuration file not found');
            }
            
            public function saveConfig($env, $config) {
                $config_file = $this->config_dir . $env . '.php';
                $config_data = '<?php return ' . var_export($config, true) . ';';
                
                file_put_contents($config_file, $config_data);
            }
        }
        
        $manager = new ConfigManager();
        $config = $manager->loadConfig($_GET['env']);
        
        // Attack: ?env=../../../etc/passwd
        // Results in: ./config/../../../etc/passwd.php -> /etc/passwd.php
        """
      },
      fixed: %{
        "Input validation and basename" => ~S"""
        // File download - SECURE
        if (isset($_GET['file'])) {
            // Use basename to prevent directory traversal
            $filename = basename($_GET['file']);
            
            // Additional validation: only allow alphanumeric, dots, dashes
            if (!preg_match('/^[a-zA-Z0-9._-]+$/', $filename)) {
                die('Invalid filename');
            }
            
            $filepath = './downloads/' . $filename;
            
            // Verify file exists and is within downloads directory
            $realpath = realpath($filepath);
            $downloads_dir = realpath('./downloads/');
            
            if ($realpath && strpos($realpath, $downloads_dir) === 0 && file_exists($realpath)) {
                header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename="' . $filename . '"');
                readfile($realpath);
            } else {
                http_response_code(404);
                echo "File not found";
            }
        }
        """,
        "Allowlist approach" => ~S"""
        // Template system - SECURE
        // Define allowed templates and themes
        $allowed_templates = ['home', 'about', 'contact', 'products', 'services'];
        $allowed_themes = ['standard', 'dark', 'mobile'];
        
        $template = $_GET['template'] ?? 'home';
        $theme = $_GET['theme'] ?? 'standard';
        
        // Validate against allowlists
        if (!in_array($template, $allowed_templates)) {
            $template = 'home';
        }
        
        if (!in_array($theme, $allowed_themes)) {
            $theme = 'standard';
        }
        
        // Construct safe path
        $template_path = './themes/' . $theme . '/templates/' . $template . '.php';
        
        // Double-check with realpath
        $real_template_path = realpath($template_path);
        $themes_dir = realpath('./themes/');
        
        if ($real_template_path && strpos($real_template_path, $themes_dir) === 0) {
            include $real_template_path;
        } else {
            include './themes/standard/templates/error.php';
        }
        """,
        "Mapping approach" => ~S"""
        // Log viewing system - SECURE
        function viewLog() {
            // Use mapping instead of direct file construction
            $log_mapping = [
                'app' => '/var/log/myapp/application.log',
                'error' => '/var/log/myapp/error.log',
                'access' => '/var/log/myapp/access.log',
                'debug' => '/var/log/myapp/debug.log'
            ];
            
            $requested_log = $_POST['logfile'] ?? 'app';
            
            if (!array_key_exists($requested_log, $log_mapping)) {
                echo "Invalid log file requested";
                return;
            }
            
            $log_path = $log_mapping[$requested_log];
            
            // Verify file exists and is readable
            if (file_exists($log_path) && is_readable($log_path)) {
                $contents = file_get_contents($log_path);
                echo '<pre>' . htmlspecialchars($contents) . '</pre>';
            } else {
                echo "Log file not accessible";
            }
        }
        """,
        "Class-based validation" => ~S"""
        // Configuration management - SECURE
        class SecureConfigManager {
            private $config_dir = './config/';
            private $allowed_environments = ['dev', 'staging', 'prod', 'test'];
            
            public function loadConfig($env) {
                // Validate environment name
                if (!$this->isValidEnvironment($env)) {
                    throw new InvalidArgumentException('Invalid environment name');
                }
                
                $config_file = $this->config_dir . $env . '.php';
                
                // Use realpath to resolve any symbolic links or relative paths
                $real_config_path = realpath($config_file);
                $real_config_dir = realpath($this->config_dir);
                
                // Ensure the resolved path is within the config directory
                if (!$real_config_path || strpos($real_config_path, $real_config_dir) !== 0) {
                    throw new SecurityException('Path traversal attempt detected');
                }
                
                if (file_exists($real_config_path)) {
                    return include $real_config_path;
                }
                
                throw new Exception('Configuration file not found');
            }
            
            public function saveConfig($env, $config) {
                if (!$this->isValidEnvironment($env)) {
                    throw new InvalidArgumentException('Invalid environment name');
                }
                
                $config_file = $this->config_dir . $env . '.php';
                $real_config_path = realpath(dirname($config_file)) . '/' . basename($config_file);
                $real_config_dir = realpath($this->config_dir);
                
                if (strpos($real_config_path, $real_config_dir) !== 0) {
                    throw new SecurityException('Path traversal attempt detected');
                }
                
                $config_data = '<?php return ' . var_export($config, true) . ';';
                file_put_contents($real_config_path, $config_data, LOCK_EX);
            }
            
            private function isValidEnvironment($env) {
                return in_array($env, $this->allowed_environments) && 
                       preg_match('/^[a-z]+$/', $env);
            }
        }
        
        try {
            $manager = new SecureConfigManager();
            $config = $manager->loadConfig($_GET['env']);
        } catch (Exception $e) {
            error_log('Config loading error: ' . $e->getMessage());
            die('Invalid configuration requested');
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
    Path traversal is a critical web security vulnerability that enables attackers to access
    files and directories outside the intended application scope. This vulnerability occurs
    when applications use user-supplied input to construct file paths without proper validation,
    allowing attackers to manipulate the path to access sensitive files on the server.
    
    ## Understanding Path Traversal Attacks
    
    ### The Basic Mechanism
    
    Path traversal exploits the file system's directory navigation features by using relative
    path sequences to "climb" up the directory tree:
    
    ```
    Normal request: /download.php?file=document.pdf
    Attack request:  /download.php?file=../../../etc/passwd
    ```
    
    The attack uses "../" sequences (dot-dot-slash) to navigate up directory levels,
    eventually reaching system files outside the application's intended directory.
    
    ### Common Vulnerable PHP Functions
    
    #### File Reading Functions
    ```php
    // VULNERABLE - user controls file path
    $content = file_get_contents('./uploads/' . $_GET['file']);
    
    // Attack: ?file=../../../etc/passwd
    // Result: Reads /etc/passwd instead of intended upload file
    ```
    
    #### File Inclusion Functions
    ```php
    // VULNERABLE - dynamic include with user input
    include('./templates/' . $_GET['template'] . '.php');
    
    // Attack: ?template=../../../etc/passwd%00
    // Result: Includes system file (null byte truncates .php)
    ```
    
    #### File Opening Functions
    ```php
    // VULNERABLE - file handle creation with user path
    $handle = fopen('./logs/' . $_POST['logfile'], 'r');
    
    // Attack: logfile=../../../etc/shadow
    // Result: Opens system password file
    ```
    
    ## Attack Techniques and Variations
    
    ### Basic Directory Traversal
    The simplest form uses relative path sequences:
    ```
    ../../../etc/passwd
    ..\\..\\..\\windows\\system32\\drivers\\etc\\hosts
    ```
    
    ### URL Encoding
    To bypass basic filters that block "../":
    ```
    %2e%2e%2f%2e%2e%2f%2e%2e%2f
    %2e%2e%5c%2e%2e%5c%2e%2e%5c
    ```
    
    ### Double URL Encoding
    For applications that decode input multiple times:
    ```
    %252e%252e%252f%252e%252e%252f%252e%252e%252f
    ```
    
    ### Unicode Encoding
    Using Unicode representations of path separators:
    ```
    %c0%ae%c0%ae%c0%af
    %c1%9c
    ```
    
    ### Null Byte Injection (PHP < 5.3.4)
    Truncating file extensions to bypass restrictions:
    ```php
    include($_GET['file'] . '.php');
    // Attack: file=../../../etc/passwd%00
    // Result: include('../../../etc/passwd')
    ```
    
    ### Mixed Case and Alternate Representations
    ```
    ..\\..\\..\\\
    ./.././.././.././
    ```
    
    ## Real-World Target Files
    
    ### Unix/Linux Systems
    - `/etc/passwd` - User account information
    - `/etc/shadow` - Password hashes (if readable)
    - `/etc/hosts` - Host name mappings
    - `/proc/version` - Kernel version information
    - `/proc/cmdline` - Boot parameters
    - `~/.ssh/id_rsa` - SSH private keys
    - `/var/log/apache2/access.log` - Web server logs
    
    ### Windows Systems
    - `C:\\windows\\system32\\drivers\\etc\\hosts`
    - `C:\\windows\\win.ini`
    - `C:\\boot.ini`
    - `C:\\windows\\system32\\config\\SAM`
    
    ### Application-Specific Files
    - Database configuration files
    - Application source code
    - Backup files (.bak, .backup, .old)
    - Log files containing sensitive information
    - SSH keys and certificates
    
    ## Advanced Attack Scenarios
    
    ### Log Poisoning via Path Traversal
    ```php
    // Step 1: Access log file via path traversal
    file_get_contents('./logs/' . $_GET['file']);
    // Attack: ?file=../../../var/log/apache2/access.log
    
    // Step 2: Poison log with PHP code via User-Agent
    // User-Agent: <?php system($_GET['cmd']); ?>
    
    // Step 3: Include poisoned log file
    include('./logs/' . $_GET['file']);
    // Result: Code execution via log file inclusion
    ```
    
    ### Configuration File Manipulation
    ```php
    // Access application config through path traversal
    $config = file_get_contents('./config/' . $_GET['env'] . '.php');
    
    // Attack reveals database credentials:
    // ?env=../../../var/www/html/wp-config
    ```
    
    ### Source Code Disclosure
    ```php
    // Reading application source code
    $content = file_get_contents('./pages/' . $_GET['page']);
    
    // Attack: ?page=../admin/login.php
    // Result: Reveals authentication logic and potential vulnerabilities
    ```
    
    ## Prevention Strategies
    
    ### Input Validation and Sanitization
    
    #### Use basename() for Filename Extraction
    ```php
    // SECURE - strips directory components
    $filename = basename($_GET['file']);
    $content = file_get_contents('./uploads/' . $filename);
    ```
    
    #### Allowlist Validation
    ```php
    // SECURE - restrict to known safe files
    $allowed_files = ['report.pdf', 'manual.doc', 'readme.txt'];
    $file = $_GET['file'];
    
    if (in_array($file, $allowed_files)) {
        $content = file_get_contents('./downloads/' . $file);
    }
    ```
    
    #### Character Validation
    ```php
    // SECURE - only allow safe characters
    if (preg_match('/^[a-zA-Z0-9._-]+$/', $_GET['file'])) {
        $content = file_get_contents('./uploads/' . $_GET['file']);
    }
    ```
    
    ### Path Resolution and Validation
    
    #### Using realpath() for Path Validation
    ```php
    // SECURE - resolve and validate final path
    $requested_file = './uploads/' . $_GET['file'];
    $real_path = realpath($requested_file);
    $uploads_dir = realpath('./uploads/');
    
    if ($real_path && strpos($real_path, $uploads_dir) === 0) {
        $content = file_get_contents($real_path);
    }
    ```
    
    #### Directory Containment Checks
    ```php
    function isPathSafe($path, $allowed_dir) {
        $real_path = realpath($path);
        $real_allowed = realpath($allowed_dir);
        
        return $real_path && $real_allowed && 
               strpos($real_path, $real_allowed) === 0;
    }
    ```
    
    ### Alternative Approaches
    
    #### File Mapping Systems
    ```php
    // Map user input to actual files
    $file_mapping = [
        'user_manual' => './docs/manual.pdf',
        'quick_start' => './docs/quickstart.pdf',
        'api_docs' => './docs/api.pdf'
    ];
    
    $requested = $_GET['document'];
    if (isset($file_mapping[$requested])) {
        readfile($file_mapping[$requested]);
    }
    ```
    
    #### Database-Driven File Access
    ```php
    // Store file metadata in database
    $stmt = $pdo->prepare("SELECT filepath FROM files WHERE id = ? AND user_id = ?");
    $stmt->execute([$_GET['file_id'], $_SESSION['user_id']]);
    $file = $stmt->fetch();
    
    if ($file && file_exists($file['filepath'])) {
        readfile($file['filepath']);
    }
    ```
    
    ## Security Testing
    
    ### Manual Testing Payloads
    ```
    ../
    ..\\\
    ..;/
    ../../../etc/passwd
    ..\\..\\..\\windows\\win.ini
    ....//....//....//etc/passwd
    %2e%2e%2f%2e%2e%2f%2e%2e%2f
    %252e%252e%252f
    %c0%ae%c0%ae%c0%af
    ..%252f..%252f..%252f
    ```
    
    ### Automated Testing
    Use tools like:
    - Burp Suite's path traversal payloads
    - OWASP ZAP's directory traversal scanner
    - Custom scripts with wordlists
    
    ## Framework-Specific Considerations
    
    ### Laravel
    ```php
    // Use Laravel's safe path helpers
    Storage::disk('local')->get($filename);  // Confined to storage path
    File::get(storage_path('app/' . $filename));  // Safe path construction
    ```
    
    ### Symfony
    ```php
    // Use Symfony's filesystem component
    $filesystem = new Filesystem();
    if ($filesystem->exists($path) && !$filesystem->isAbsolutePath($path)) {
        // Safe to process
    }
    ```
    
    Remember: Path traversal vulnerabilities can lead to complete information disclosure
    and potentially remote code execution. Always validate and sanitize file paths,
    use allowlist-based validation, and implement proper access controls.
    """
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual vulnerabilities and false positives
  by analyzing the context of file access operations and checking for safety measures.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Php.PathTraversal.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:min_confidence, :rules]
      
      iex> enhancement = RsolvApi.Security.Patterns.Php.PathTraversal.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
      
      iex> enhancement = RsolvApi.Security.Patterns.Php.PathTraversal.ast_enhancement()
      iex> length(enhancement.rules)
      4
  """
  @impl true
  def ast_enhancement do
    %{
      rules: [
        %{
          type: "file_access_functions",
          description: "PHP functions that access or include files",
          functions: [
            "file_get_contents",
            "fopen",
            "readfile",
            "include",
            "include_once",
            "require",
            "require_once",
            "file",
            "readdir",
            "scandir"
          ],
          contexts: [
            "file_download_systems",
            "template_loading",
            "configuration_management",
            "log_viewing",
            "document_processing"
          ]
        },
        %{
          type: "path_validation",
          description: "Functions and techniques that validate or sanitize file paths",
          functions: [
            "basename",
            "realpath",
            "pathinfo",
            "dirname",
            "is_readable",
            "file_exists",
            "is_file"
          ],
          validation_patterns: [
            "in_array($file, $allowed_files)",
            "preg_match('/^[a-zA-Z0-9._-]+$/', $file)",
            "strpos($real_path, $safe_dir) === 0",
            "filter_var($file, FILTER_SANITIZE_STRING)"
          ]
        },
        %{
          type: "context_analysis",
          description: "Analyze usage context to determine vulnerability risk",
          high_risk_patterns: [
            "Direct concatenation of user input with file paths",
            "File operations without path validation",
            "Include/require with user-controlled paths",
            "File download systems accepting arbitrary filenames",
            "Configuration loading with user-specified environments"
          ],
          mitigation_indicators: [
            "basename() used before file operations",
            "realpath() validation of final paths",
            "in_array() allowlist checking",
            "preg_match() pattern validation",
            "strpos() directory containment checks"
          ],
          false_positive_patterns: [
            "Hardcoded file paths without user input",
            "Pre-validated variables from internal sources",
            "File operations in unit tests or fixtures",
            "Static includes without dynamic components",
            "Database-driven file access without direct path construction"
          ]
        },
        %{
          type: "user_input_analysis",
          description: "Identify sources and handling of user input in file operations",
          dangerous_sources: [
            "$_GET",
            "$_POST",
            "$_REQUEST",
            "$_COOKIE",
            "$_FILES",
            "file_get_contents('php://input')",
            "command line arguments",
            "database results from user queries"
          ],
          safe_patterns: [
            "Constants and hardcoded strings",
            "Configuration values from secure sources",
            "Database IDs mapped to actual file paths",
            "Session variables set by application logic",
            "Validated and sanitized user input"
          ]
        }
      ],
      min_confidence: 0.7
    }
  end
end