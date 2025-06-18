defmodule RsolvApi.Security.Patterns.Php.ExtractUsage do
  @moduledoc """
  Pattern for detecting dangerous extract() usage in PHP.
  
  This pattern identifies when PHP applications use the extract() function with
  user input, potentially allowing attackers to overwrite internal variables and
  manipulate application behavior.
  
  ## Vulnerability Details
  
  The extract() function in PHP imports variables from an array into the current
  symbol table. When used with user-controlled arrays like $_GET, $_POST, or
  $_REQUEST, it can lead to severe security issues by allowing attackers to
  overwrite existing variables, including security-critical ones.
  
  ### Attack Example
  ```php
  // Vulnerable code
  $is_admin = false;
  extract($_POST); // Attacker sends POST: is_admin=1
  
  if ($is_admin) {
      // Attacker gains admin access!
      delete_all_users();
  }
  ```
  
  The extract() function essentially provides the same dangerous functionality
  as the deprecated register_globals, allowing external input to directly
  create or overwrite variables in the current scope.
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "php-extract-usage",
      name: "Variable Overwrite via extract()",
      description: "Using extract() on user input can overwrite variables",
      type: :input_validation,
      severity: :high,
      languages: ["php"],
      regex: ~r/extract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)(?!.*EXTR_SKIP)/,
      default_tier: :ai,
      cwe_id: "CWE-621",
      owasp_category: "A03:2021",
      recommendation: "Avoid extract() on user input or use EXTR_SKIP flag",
      test_cases: %{
        vulnerable: [
          ~S|extract($_POST);|,
          ~S|extract($_GET);|,
          ~S|extract($_REQUEST);|,
          ~S|extract($_POST, EXTR_OVERWRITE);|
        ],
        safe: [
          ~S|extract($_POST, EXTR_SKIP);|,
          ~S|$name = $_POST['name'] ?? '';|,
          ~S|$validated_data = validate($_POST); extract($validated_data);|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Variable extraction vulnerabilities occur when PHP applications use the extract()
      function to import variables from user-controlled arrays into the current symbol
      table. This can lead to critical security issues including authentication bypass,
      privilege escalation, and arbitrary code execution.
      
      The extract() function takes an associative array and creates variables in the
      current scope using the array keys as variable names and array values as variable
      values. When applied to superglobal arrays like $_POST, $_GET, $_REQUEST, or
      $_COOKIE, attackers can inject arbitrary variables into the application's execution
      context.
      
      ### How Variable Overwriting Works
      
      **Basic Overwrite Attack**:
      ```php
      // Application code
      $authenticated = false;
      $user_role = 'guest';
      
      // Dangerous extract
      extract($_POST); // POST: authenticated=1&user_role=admin
      
      // Now $authenticated = '1' and $user_role = 'admin'
      if ($authenticated) {
          if ($user_role === 'admin') {
              // Attacker has admin access!
          }
      }
      ```
      
      **Configuration Override**:
      ```php
      $db_host = 'localhost';
      $db_user = 'app_user';
      $debug_mode = false;
      
      extract($_REQUEST); // REQUEST: db_host=evil.com&debug_mode=1
      
      // Attacker can redirect database connections or enable debug mode
      ```
      
      ### Register Globals Revival
      
      The extract() function essentially recreates the dangerous register_globals
      functionality that was deprecated and removed from PHP due to security concerns.
      It allows external input to directly create variables, leading to:
      
      - **Authentication Bypass**: Overwriting authentication flags
      - **Privilege Escalation**: Changing user roles or permissions
      - **Configuration Tampering**: Modifying application settings
      - **Logic Manipulation**: Altering control flow variables
      - **Session Hijacking**: Overwriting session variables
      
      ### Extract Flags and Their Risks
      
      PHP provides several flags for extract(), but many are still dangerous:
      
      - **EXTR_OVERWRITE** (default): Overwrites existing variables - DANGEROUS
      - **EXTR_IF_EXISTS**: Only overwrites if variable exists - STILL DANGEROUS
      - **EXTR_PREFIX_SAME**: Prefixes collisions - Can still pollute namespace
      - **EXTR_PREFIX_ALL**: Prefixes all - Safer but still risky
      - **EXTR_SKIP**: Skips existing variables - RECOMMENDED if extract is necessary
      
      Even with EXTR_SKIP, new variables can still be injected, potentially affecting
      application logic that checks for variable existence.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-621",
          title: "Variable Extraction Error",
          url: "https://cwe.mitre.org/data/definitions/621.html"
        },
        %{
          type: :owasp,
          id: "A03:2021",
          title: "OWASP Top 10 2021 - A03 Injection",
          url: "https://owasp.org/Top10/A03_2021-Injection/"
        },
        %{
          type: :php_manual,
          id: "function.extract",
          title: "PHP Manual - extract() function",
          url: "https://www.php.net/manual/en/function.extract.php"
        },
        %{
          type: :research,
          id: "extract_vulnerability",
          title: "External Variable Modification via extract()",
          url: "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/External%20Variable%20Modification/README.md"
        },
        %{
          type: :research,
          id: "register_globals_danger",
          title: "Why Register Globals is Dangerous",
          url: "https://www.php.net/manual/en/security.globals.php"
        }
      ],
      attack_vectors: [
        "Authentication bypass: extract($_POST) with POST data 'is_admin=1'",
        "Privilege escalation: Overwriting $user_role or $permissions variables",
        "Configuration override: Changing $db_host, $api_key, or $debug_mode",
        "Session manipulation: Injecting $_SESSION variables through extract",
        "Logic flow alteration: Overwriting control variables like $step or $action",
        "Error handling bypass: Setting $error = false to skip validation",
        "Include path manipulation: Changing $template_dir or $plugin_path"
      ],
      real_world_impact: [
        "Complete authentication bypass allowing unauthorized access",
        "Elevation to administrative privileges in web applications",
        "Database credential theft through configuration variable override",
        "Remote code execution via template or include path manipulation",
        "Financial loss through e-commerce variable manipulation",
        "Data breaches via debug mode activation",
        "Reputation damage from defaced websites"
      ],
      cve_examples: [
        %{
          id: "CVE-2006-7079",
          description: "PHP app uses extract for register_globals compatibility enabling path traversal",
          severity: "high",
          cvss: 7.5,
          note: "Chain attack: extract() enables variable overwrite leading to directory traversal"
        },
        %{
          id: "CVE-2025-1949",
          description: "ZZCMS 2025 extract() vulnerability allowing authentication bypass",
          severity: "critical",
          cvss: 9.8,
          note: "Direct use of extract($_POST) allows overwriting admin session variables"
        },
        %{
          id: "CVE-2024-41229",
          description: "VMware Cloud Foundation variable extraction vulnerability",
          severity: "high",
          cvss: 8.8,
          note: "extract() usage in authentication flow enables privilege escalation"
        },
        %{
          id: "CVE-2018-19518",
          description: "University of Washington IMAP Server extract() vulnerability",
          severity: "critical",
          cvss: 9.8,
          note: "extract($_GET) in webmail interface allows authentication bypass"
        }
      ],
      detection_notes: """
      This pattern detects extract() usage vulnerabilities by identifying PHP code that:
      
      1. **Function Analysis**: Matches the extract() function call
      2. **Parameter Inspection**: Looks for user input superglobals as parameters:
         - Direct usage: extract($_POST)
         - Array access: extract($_GET['data'])
         - With flags: extract($_REQUEST, EXTR_OVERWRITE)
      
      3. **Safe Usage Detection**: Excludes patterns with EXTR_SKIP flag:
         - extract($_POST, EXTR_SKIP) is considered safer
         - Still not recommended but less dangerous
      
      4. **Input Sources**: Detects all PHP superglobals:
         - $_GET - URL parameters
         - $_POST - Form data
         - $_REQUEST - Combined GET/POST/COOKIE
         - $_COOKIE - Cookie values
      
      The pattern uses a negative lookahead to exclude EXTR_SKIP usage:
      extract\\s*\\(\\s*\\$_(GET|POST|REQUEST|COOKIE)(?!.*EXTR_SKIP)
      """,
      safe_alternatives: [
        "Access array elements directly: $name = $_POST['name'] ?? ''",
        "Use filter_input() for safe access: $id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT)",
        "Create specific variables: $username = htmlspecialchars($_POST['username'] ?? '')",
        "Use EXTR_SKIP if extract is absolutely necessary: extract($_POST, EXTR_SKIP)",
        "Validate and whitelist before extraction: extract(validate_input($_POST))",
        "Use request objects in frameworks: $request->input('name')",
        "Implement proper input handling classes instead of extract()"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing that extract() with prefixes is safe (still allows injection)",
          "Using extract() for convenience without understanding security implications",
          "Thinking EXTR_IF_EXISTS prevents security issues (it doesn't)",
          "Not realizing extract() affects the entire current scope",
          "Using extract() in global scope affecting entire application",
          "Forgetting that numeric keys in arrays create variables like $0, $1",
          "Assuming framework sanitization prevents extract() vulnerabilities"
        ],
        historical_context: [
          "register_globals was removed in PHP 5.4 due to security issues",
          "extract() provides similar dangerous functionality",
          "Many legacy applications still use extract() extensively",
          "Modern frameworks avoid extract() in favor of request objects",
          "The function exists for backwards compatibility but should be avoided"
        ],
        safe_extract_patterns: [
          "Only use extract() on trusted, validated data",
          "Always use EXTR_SKIP to prevent overwriting",
          "Limit scope by using extract() only in isolated functions",
          "Prefix all extracted variables: extract($data, EXTR_PREFIX_ALL, 'safe_')",
          "Document every extract() usage with security justification",
          "Consider refactoring to eliminate extract() entirely"
        ]
      }
    }
  end

  @doc """
  Returns test cases for the extract usage pattern.
  
  ## Examples
  
      iex> test_cases = RsolvApi.Security.Patterns.Php.ExtractUsage.test_cases()
      iex> length(test_cases.positive)
      8
      
      iex> test_cases = RsolvApi.Security.Patterns.Php.ExtractUsage.test_cases()
      iex> length(test_cases.negative)
      6
  """
  @impl true  
  def test_cases do
    %{
      positive: [
        %{
          code: ~S|extract($_POST);|,
          description: "Direct extraction of POST data"
        },
        %{
          code: ~S|extract($_GET);|,
          description: "Direct extraction of GET data"
        },
        %{
          code: ~S|extract($_REQUEST);|,
          description: "Direct extraction of REQUEST data"
        },
        %{
          code: ~S|extract($_COOKIE);|,
          description: "Direct extraction of COOKIE data"
        },
        %{
          code: ~S|extract($_POST, EXTR_OVERWRITE);|,
          description: "Explicit overwrite flag (default behavior)"
        },
        %{
          code: ~S|extract($_GET, EXTR_IF_EXISTS);|,
          description: "Only overwrite existing variables (still dangerous)"
        },
        %{
          code: ~S|extract($_REQUEST, EXTR_PREFIX_SAME, "p");|,
          description: "Prefix on collision (still allows new variables)"
        },
        %{
          code: ~S|extract($_POST['user_data']);|,
          description: "Extract from user-controlled array element"
        }
      ],
      negative: [
        %{
          code: ~S|extract($safe_data);|,
          description: "Extract from non-user-input variable"
        },
        %{
          code: ~S|extract($_POST, EXTR_SKIP);|,
          description: "Using EXTR_SKIP to prevent overwriting"
        },
        %{
          code: ~S|$name = $_POST['name'];|,
          description: "Direct variable assignment instead"
        },
        %{
          code: ~S|// extract($_POST);|,
          description: "Commented out extract"
        },
        %{
          code: ~S|$validated = validate($_POST); extract($validated);|,
          description: "Extract only after validation"
        },
        %{
          code: ~S|function extract_user_data($data) { /* custom function */ }|,
          description: "Custom function, not PHP's extract()"
        }
      ]
    }
  end

  @doc """
  Returns examples of vulnerable and fixed code.
  
  ## Examples
  
      iex> examples = RsolvApi.Security.Patterns.Php.ExtractUsage.examples()
      iex> Map.keys(examples)
      [:vulnerable, :fixed]
  """
  @impl true
  def examples do
    %{
      vulnerable: %{
        "Authentication bypass" => """
        // VULNERABLE: Direct extract allows variable injection
        $is_authenticated = false;
        $user_role = 'guest';
        
        extract($_POST);
        // Attacker sends: POST is_authenticated=1&user_role=admin
        
        if ($is_authenticated) {
            if ($user_role === 'admin') {
                show_admin_panel(); // Unauthorized access!
            }
        }
        """,
        "Configuration override" => """
        // VULNERABLE: Settings can be overwritten
        $db_host = 'localhost';
        $db_name = 'myapp';
        $debug = false;
        
        extract($_REQUEST); // REQUEST: db_host=attacker.com&debug=1
        
        $connection = new PDO("mysql:host=$db_host;dbname=$db_name", $user, $pass);
        // Connects to attacker's server!
        """,
        "Variable pollution" => """
        // VULNERABLE: New variables can be injected
        extract($_GET);
        
        // Attacker can inject any variable
        // GET: admin_mode=1&bypass_checks=1&error_reporting=0
        
        if (isset($admin_mode)) {
            // Variable didn't exist before but does now!
            grant_admin_access();
        }
        """
      },
      fixed: %{
        "Direct access" => """
        // SECURE: Access array elements directly
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';
        $remember = isset($_POST['remember']) ? true : false;
        
        // Variables are explicitly defined and typed
        if (authenticate($username, $password)) {
            login_user($username, $remember);
        }
        """,
        "EXTR_SKIP flag" => """
        // SAFER: Use EXTR_SKIP to prevent overwriting
        $is_admin = false;
        $user_role = 'guest';
        
        // EXTR_SKIP won't overwrite existing variables
        extract($_POST, EXTR_SKIP);
        
        // $is_admin and $user_role remain unchanged
        // But new variables can still be injected!
        """,
        "Validation first" => """
        // SECURE: Validate and whitelist before any extraction
        function get_safe_user_data($input) {
            $allowed_fields = ['name', 'email', 'phone'];
            $safe_data = [];
            
            foreach ($allowed_fields as $field) {
                if (isset($input[$field])) {
                    $safe_data[$field] = filter_var(
                        $input[$field], 
                        FILTER_SANITIZE_STRING
                    );
                }
            }
            
            return $safe_data;
        }
        
        // Only extract validated data
        $user_data = get_safe_user_data($_POST);
        extract($user_data, EXTR_SKIP);
        """
      }
    }
  end

  @doc """
  Returns educational description of the vulnerability.
  
  ## Examples
  
      iex> desc = RsolvApi.Security.Patterns.Php.ExtractUsage.vulnerability_description()
      iex> desc =~ "extract"
      true
      
      iex> desc = RsolvApi.Security.Patterns.Php.ExtractUsage.vulnerability_description()
      iex> desc =~ "variable"
      true
      
      iex> desc = RsolvApi.Security.Patterns.Php.ExtractUsage.vulnerability_description()
      iex> desc =~ "overwrite"
      true
  """
  @impl true
  def vulnerability_description do
    """
    Variable extraction vulnerabilities occur when PHP applications use the extract() 
    function on user-controlled input, allowing attackers to inject or overwrite 
    variables in the current scope and potentially bypass security controls.
    
    The extract() function imports variables from an array into the current symbol 
    table, using array keys as variable names. When used with superglobals like 
    $_POST, $_GET, or $_REQUEST, it essentially recreates the dangerous 
    register_globals functionality.
    
    ## Security Impact
    
    **Authentication Bypass**: Attackers can overwrite authentication flags or 
    user role variables to gain unauthorized access to protected functionality.
    
    **Configuration Tampering**: Critical configuration variables like database 
    credentials, API keys, or debug flags can be overwritten by user input.
    
    **Logic Manipulation**: Control flow variables can be injected or modified, 
    allowing attackers to bypass validation checks or alter application behavior.
    
    ## Attack Scenarios
    
    1. **Variable Injection**: Creating new variables that affect logic
       - Setting $is_admin when it doesn't exist
       - Injecting $skip_validation flags
    
    2. **Variable Overwriting**: Replacing existing values
       - Changing $user_role from 'guest' to 'admin'
       - Overwriting $authenticated from false to true
    
    3. **Namespace Pollution**: Flooding the scope with variables
       - Creating numerous variables to exhaust memory
       - Interfering with normal variable usage
    
    ## Prevention
    
    The safest approach is to avoid extract() entirely, especially with user input. 
    Access array elements directly, use proper input validation, and leverage 
    modern PHP frameworks that provide secure request handling mechanisms.
    """
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual vulnerabilities and false positives
  by analyzing extract() usage context and the safety flags used.

  ## Examples

      iex> enhancement = RsolvApi.Security.Patterns.Php.ExtractUsage.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:min_confidence, :rules]
      
      iex> enhancement = RsolvApi.Security.Patterns.Php.ExtractUsage.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
      
      iex> enhancement = RsolvApi.Security.Patterns.Php.ExtractUsage.ast_enhancement()
      iex> length(enhancement.rules)
      4
  """
  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.8,
      rules: [
        %{
          type: "extract_functions",
          description: "Identify extract and similar variable import functions",
          functions: [
            "extract", "import_request_variables", "parse_str"
          ]
        },
        %{
          type: "user_input_analysis",
          description: "Detect user input sources being extracted",
          dangerous_sources: ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER"],
          safe_sources: ["$config", "$settings", "$validated_data"]
        },
        %{
          type: "flag_analysis",
          description: "Check extraction flags for safety",
          safe_flags: ["EXTR_SKIP", "EXTR_PREFIX_ALL with validation"],
          dangerous_flags: ["EXTR_OVERWRITE", "EXTR_IF_EXISTS", "EXTR_PREFIX_SAME"],
          default_behavior: "EXTR_OVERWRITE (most dangerous)"
        },
        %{
          type: "context_validation",
          description: "Validate extraction context and scope",
          exclude_patterns: [
            "test", "mock", "example", "demo",
            "// extract", "/* extract", "template"
          ],
          high_risk_contexts: [
            "authentication", "authorization", "session",
            "config", "database", "admin", "privilege"
          ]
        }
      ]
    }
  end
end