defmodule RsolvApi.Security.Patterns.Php.RegisterGlobals do
  @moduledoc """
  Pattern for detecting register_globals dependency in PHP.
  
  This pattern identifies code that appears to rely on the deprecated
  register_globals feature where uninitialized variables might be coming
  from user input.
  
  ## Vulnerability Details
  
  The register_globals directive was a PHP configuration option that automatically
  created global variables from GET, POST, COOKIE, and SERVER variables. This
  led to severe security vulnerabilities as attackers could inject arbitrary
  variables into the application's execution context.
  
  ### Attack Example
  ```php
  // Vulnerable code - $authenticated not initialized
  if ($authenticated) {
      // Attacker can set ?authenticated=1 in URL
      show_admin_panel();
  }
  ```
  
  While register_globals was removed in PHP 5.4, legacy code or code written
  with bad practices may still exhibit similar vulnerabilities through lack
  of proper variable initialization.
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "php-register-globals",
      name: "Register Globals Dependency",
      description: "Code that might rely on register_globals behavior",
      type: :input_validation,
      severity: :medium,
      languages: ["php"],
      regex: ~r/if\s*\(\s*[!&|(\s]*\$(?!_)(authenticated|admin|user_id|logged_in|admin_mode|privileged|bypass_auth)\b/,
      default_tier: :public,
      cwe_id: "CWE-473",
      owasp_category: "A04:2021",
      recommendation: "Initialize all variables and don't rely on register_globals",
      test_cases: %{
        vulnerable: [
          ~S|if ($authenticated) { show_content(); }|,
          ~S|if ($admin) { admin_panel(); }|,
          ~S|if ($user_id) { echo "Welcome user $user_id"; }|,
          ~S|if ($logged_in) { display_profile(); }|
        ],
        safe: [
          ~S|$authenticated = isset($_SESSION['authenticated']) ? $_SESSION['authenticated'] : false;
if ($authenticated) {|,
          ~S|if ($_SESSION['authenticated']) { show_content(); }|,
          ~S|if (defined('AUTHENTICATED')) {|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Register globals vulnerabilities occur when PHP applications rely on uninitialized
      variables that could be controlled by user input. While the register_globals
      directive was removed in PHP 5.4, legacy code or poorly written new code may
      still exhibit similar patterns.
      
      When register_globals was enabled, PHP would automatically create variables from
      GET, POST, COOKIE, and SERVER data. For example, a request to script.php?foo=bar
      would create a variable $foo with value "bar" in the global scope.
      
      ### How Register Globals Works
      
      **Without register_globals (secure):**
      ```php
      // $authenticated is undefined
      if ($authenticated) { // PHP Notice: Undefined variable
          // This block won't execute
      }
      ```
      
      **With register_globals (vulnerable):**
      ```php
      // Attacker requests: page.php?authenticated=1
      if ($authenticated) { // $authenticated = '1' from GET
          // Attacker gains access!
          show_admin_functions();
      }
      ```
      
      ### Common Vulnerable Patterns
      
      1. **Authentication Bypass**:
         - Uninitialized $authenticated, $is_logged_in variables
         - Attacker sets these via GET/POST parameters
      
      2. **Privilege Escalation**:
         - Uninitialized $is_admin, $user_role variables
         - Attacker elevates privileges through URL parameters
      
      3. **Configuration Override**:
         - Uninitialized configuration variables
         - Attacker modifies application behavior
      
      ### Modern Equivalents
      
      Even without register_globals, similar vulnerabilities can occur through:
      - Using extract() on $_GET/$_POST arrays
      - Variable variables ($$var) with user input
      - Poor initialization practices
      - Assuming variables have default values
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-473",
          title: "PHP External Variable Modification",
          url: "https://cwe.mitre.org/data/definitions/473.html"
        },
        %{
          type: :owasp,
          id: "A04:2021",
          title: "OWASP Top 10 2021 - A04 Insecure Design",
          url: "https://owasp.org/Top10/A04_2021-Insecure_Design/"
        },
        %{
          type: :php_manual,
          id: "security.globals",
          title: "PHP Manual - Using Register Globals",
          url: "https://www.php.net/manual/en/security.globals.php"
        },
        %{
          type: :research,
          id: "register_globals_removal",
          title: "PHP 5.4.0 Release - Register Globals Removed",
          url: "https://www.php.net/releases/5_4_0.php"
        }
      ],
      attack_vectors: [
        "Authentication bypass: ?authenticated=1&user_id=admin",
        "Privilege escalation: ?is_admin=1&role=administrator",
        "Session hijacking: ?PHPSESSID=stolen_session_id",
        "Configuration tampering: ?debug_mode=1&db_host=attacker.com",
        "Include path manipulation: ?include_path=/tmp/evil/",
        "Error suppression: ?display_errors=0&error_reporting=0",
        "Variable injection: ?admin_email=attacker@evil.com"
      ],
      real_world_impact: [
        "Complete authentication bypass allowing unauthorized access",
        "Privilege escalation to administrator roles",
        "Remote code execution through include path manipulation",
        "Database credential exposure through debug mode activation",
        "Session hijacking and identity theft",
        "Application configuration tampering",
        "Bypass of security checks and validation"
      ],
      cve_examples: [
        %{
          id: "CVE-2025-1134",
          description: "HospitanDoc 3.0 register_globals-style vulnerability via uninitialized variables",
          severity: "critical",
          cvss: 9.8,
          note: "Authentication bypass through uninitialized $authenticated variable"
        },
        %{
          id: "CVE-2024-50506",
          description: "GLPI register_globals emulation vulnerability in legacy compatibility",
          severity: "high",
          cvss: 8.8,
          note: "Variable injection through poor initialization practices"
        },
        %{
          id: "CVE-2023-4618",
          description: "KiteCMS authentication bypass via uninitialized variables",
          severity: "critical",
          cvss: 9.8,
          note: "Direct authentication bypass similar to register_globals"
        },
        %{
          id: "CVE-2020-8813",
          description: "Cacti graph_realtime.php register_globals style vulnerability",
          severity: "high",
          cvss: 8.8,
          note: "Variable initialization flaw allowing code execution"
        }
      ],
      detection_notes: """
      This pattern detects potential register_globals vulnerabilities by identifying:
      
      1. **Uninitialized Variable Usage**: Variables used in conditions without initialization
      2. **Security-Critical Names**: Focus on authentication/authorization variable names:
         - $authenticated, $admin, $user_id, $logged_in
         - Common security-related variable patterns
      
      3. **Conditional Context**: Variables used in if statements where they control access
      4. **Exclusion of Superglobals**: Pattern excludes $_GET, $_POST, etc. ((?!_) negative lookahead)
      
      The regex pattern:
      if\\s*\\(\\s*\\$(?!_)(authenticated|admin|user_id|logged_in)\\s*\\)
      
      This matches if statements with suspicious uninitialized variables while
      excluding PHP superglobals that start with $_.
      """,
      safe_alternatives: [
        "Always initialize variables: $authenticated = false;",
        "Use proper session management: if ($_SESSION['authenticated']) { }",
        "Implement proper authentication systems with frameworks",
        "Use filter_input() for safe input handling",
        "Enable E_NOTICE errors to catch undefined variables",
        "Use static analysis tools to detect uninitialized variables",
        "Implement strict variable scoping and initialization policies"
      ],
      additional_context: %{
        common_mistakes: [
          "Assuming variables have default values (they don't in PHP)",
          "Copy-pasting old code that relied on register_globals",
          "Not initializing variables at the start of scripts",
          "Using extract() on user input arrays",
          "Trusting that undefined variables are safe to use",
          "Not enabling error reporting in development",
          "Using @ error suppression operator hiding undefined variable warnings"
        ],
        historical_context: [
          "register_globals was enabled by default before PHP 4.2.0",
          "Deprecated in PHP 5.3.0 and removed in PHP 5.4.0",
          "Caused countless security vulnerabilities in PHP applications",
          "Led to major rewrites of popular PHP applications",
          "Still affects legacy code and poorly maintained applications"
        ],
        detection_limitations: [
          "Pattern may have false positives with properly initialized variables",
          "Cannot detect all possible variable names (focuses on common ones)",
          "May miss complex initialization patterns",
          "Requires AST analysis for accurate detection",
          "Cannot distinguish between initialized and uninitialized variables"
        ]
      }
    }
  end

  @doc """
  Returns test cases for the register globals pattern.
  
  ## Examples
  
      iex> test_cases = RsolvApi.Security.Patterns.Php.RegisterGlobals.test_cases()
      iex> length(test_cases.positive)
      8
      
      iex> test_cases = RsolvApi.Security.Patterns.Php.RegisterGlobals.test_cases()
      iex> length(test_cases.negative)
      6
  """
  @impl true  
  def test_cases do
    %{
      positive: [
        %{
          code: ~S|if ($authenticated) { show_content(); }|,
          description: "Uninitialized $authenticated variable"
        },
        %{
          code: ~S|if ($admin) { admin_panel(); }|,
          description: "Uninitialized $admin variable"
        },
        %{
          code: ~S|if ($user_id) { echo "Welcome user $user_id"; }|,
          description: "Uninitialized $user_id variable"
        },
        %{
          code: ~S|if ($logged_in) { display_profile(); }|,
          description: "Uninitialized $logged_in variable"
        },
        %{
          code: ~S|if($authenticated){|,
          description: "No spaces around condition"
        },
        %{
          code: ~S|if ( $admin ) {|,
          description: "Extra spaces in condition"
        },
        %{
          code: ~S|if ($authenticated && $user_id) {|,
          description: "Multiple suspicious variables"
        },
        %{
          code: ~S|if (!$logged_in) { redirect('/login'); }|,
          description: "Negated condition with suspicious variable"
        }
      ],
      negative: [
        %{
          code: ~S|if ($_SESSION['authenticated']) { show_content(); }|,
          description: "Using session variable properly"
        },
        %{
          code: ~S|if ($_POST['admin']) { }|,
          description: "Using POST superglobal"
        },
        %{
          code: ~S|$authenticated = false; if ($authenticated) {|,
          description: "Variable is initialized"
        },
        %{
          code: ~S|if (defined('AUTHENTICATED')) {|,
          description: "Using defined constant"
        },
        %{
          code: ~S|if ($this->authenticated) {|,
          description: "Object property, not global variable"
        },
        %{
          code: ~S|// if ($authenticated) { }|,
          description: "Commented out code"
        }
      ]
    }
  end

  @doc """
  Returns examples of vulnerable and fixed code.
  
  ## Examples
  
      iex> examples = RsolvApi.Security.Patterns.Php.RegisterGlobals.examples()
      iex> Map.keys(examples)
      [:vulnerable, :fixed]
  """
  @impl true
  def examples do
    %{
      vulnerable: %{
        "Authentication bypass" => """
        // VULNERABLE: Uninitialized variable can be set by attacker
        if ($authenticated) {
            // Attacker can access by setting ?authenticated=1
            include 'admin/dashboard.php';
            echo "Welcome administrator!";
        }
        """,
        "Privilege escalation" => """
        // VULNERABLE: Role check with uninitialized variable
        if ($is_admin) {
            delete_user($_GET['id']);
            modify_settings($_POST['config']);
        }
        
        // Attacker sets ?is_admin=1 to gain admin access
        """,
        "Multiple vulnerabilities" => """
        // VULNERABLE: Several uninitialized variables
        if ($logged_in) {
            echo "User ID: $user_id";
            
            if ($admin) {
                show_admin_menu();
            }
            
            if ($moderator) {
                show_mod_tools();  
            }
        }
        // Attacker can set all via: ?logged_in=1&user_id=1&admin=1
        """
      },
      fixed: %{
        "Explicit initialization" => """
        // SECURE: Initialize all variables explicitly
        $authenticated = false;
        $is_admin = false;
        $user_id = null;
        
        // Check authentication properly
        if (isset($_SESSION['user_id'])) {
            $authenticated = true;
            $user_id = $_SESSION['user_id'];
            $is_admin = ($_SESSION['role'] === 'admin');
        }
        
        if ($authenticated) {
            // Now safe to use
            include 'user/dashboard.php';
        }
        """,
        "Use superglobals" => """
        // SECURE: Direct session usage
        session_start();
        
        if (isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true) {
            echo "Welcome " . htmlspecialchars($_SESSION['username']);
            
            if (isset($_SESSION['role']) && $_SESSION['role'] === 'admin') {
                show_admin_panel();
            }
        }
        """,
        "Modern PHP approach" => """
        // SECURE: Using a proper authentication class
        class Auth {
            private $user = null;
            
            public function __construct() {
                session_start();
                if (isset($_SESSION['user'])) {
                    $this->user = $_SESSION['user'];
                }
            }
            
            public function isAuthenticated(): bool {
                return $this->user !== null;
            }
            
            public function isAdmin(): bool {
                return $this->user && $this->user['role'] === 'admin';
            }
        }
        
        $auth = new Auth();
        if ($auth->isAuthenticated()) {
            // Safe to proceed
        }
        """
      }
    }
  end

  @doc """
  Returns educational description of the vulnerability.
  
  ## Examples
  
      iex> desc = RsolvApi.Security.Patterns.Php.RegisterGlobals.vulnerability_description()
      iex> desc =~ "register_globals"
      true
      
      iex> desc = RsolvApi.Security.Patterns.Php.RegisterGlobals.vulnerability_description()
      iex> desc =~ "variable"
      true
      
      iex> desc = RsolvApi.Security.Patterns.Php.RegisterGlobals.vulnerability_description()
      iex> desc =~ "initialization"
      true
  """
  @impl true
  def vulnerability_description do
    """
    Register globals vulnerabilities occur when PHP applications use uninitialized 
    variables that could be controlled by user input, mimicking the dangerous 
    behavior of PHP's deprecated register_globals directive.
    
    The register_globals feature automatically created variables from GET, POST, 
    COOKIE, and SERVER data. While removed in PHP 5.4, legacy code patterns 
    still create similar vulnerabilities through poor variable initialization.
    
    ## Security Impact
    
    **Authentication Bypass**: Attackers can set authentication flags by adding 
    parameters to URLs, completely bypassing login systems.
    
    **Privilege Escalation**: User roles and permissions stored in uninitialized 
    variables can be manipulated to gain administrative access.
    
    **Application Control**: Critical configuration variables can be overwritten, 
    allowing attackers to modify application behavior.
    
    ## Attack Scenarios
    
    1. **Direct Authentication Bypass**:
       - Application checks if ($authenticated)
       - Attacker adds ?authenticated=1 to URL
       - Gains immediate access without credentials
    
    2. **Role Manipulation**:
       - Application uses uninitialized $is_admin
       - Attacker sets ?is_admin=1 parameter
       - Receives full administrative privileges
    
    3. **Session Variable Injection**:
       - Uninitialized session-like variables
       - Attacker injects session data via GET/POST
       - Hijacks user sessions or creates fake ones
    
    ## Prevention
    
    Always initialize variables before use, utilize PHP's superglobal arrays 
    directly ($_SESSION, $_POST, etc.), and enable error reporting to catch 
    undefined variable usage during development.
    """
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual vulnerabilities and false positives
  by analyzing variable initialization and the context of variable usage.

  ## Examples

      iex> enhancement = RsolvApi.Security.Patterns.Php.RegisterGlobals.ast_enhancement()
      iex> Map.keys(enhancement)
      [:min_confidence, :rules]
      
      iex> enhancement = RsolvApi.Security.Patterns.Php.RegisterGlobals.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
      
      iex> enhancement = RsolvApi.Security.Patterns.Php.RegisterGlobals.ast_enhancement()
      iex> length(enhancement.rules)
      4
  """
  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.7,
      rules: [
        %{
          type: "variable_analysis",
          description: "Identify security-critical uninitialized variables",
          suspicious_variables: [
            "authenticated", "admin", "user_id", "logged_in",
            "authorized", "privileged", "access_level", "permission",
            "is_admin", "is_user", "is_logged_in", "is_authenticated",
            "role", "user_role", "user_type", "user_level"
          ],
          initialization_patterns: [
            "= false", "= null", "= 0", "= ''",
            "isset(", "!empty(", "array_key_exists("
          ]
        },
        %{
          type: "context_analysis",
          description: "Check if variables are used in security contexts",
          security_contexts: [
            "authentication", "authorization", "access control",
            "permission check", "admin check", "user verification"
          ],
          dangerous_operations: [
            "include", "require", "eval", "system", "exec",
            "file_get_contents", "fopen", "unlink", "mysql_query"
          ]
        },
        %{
          type: "initialization_tracking",
          description: "Track if variables are initialized before use",
          safe_patterns: [
            "$var = value", "isset($_SESSION[", "isset($_COOKIE[",
            "filter_input(", "filter_var(", "$this->", "self::",
            "defined(", "constant("
          ],
          framework_patterns: [
            "$request->get(", "$app->param(", "Input::get(",
            "$_ENV[", "getenv(", "config("
          ]
        },
        %{
          type: "scope_analysis", 
          description: "Analyze variable scope and initialization",
          exclude_patterns: [
            "function parameters", "foreach variables", "class properties",
            "global declaration", "static variables", "constants"
          ],
          include_patterns: [
            "global scope", "function scope without init",
            "conditional blocks", "loop bodies"
          ]
        }
      ]
    }
  end
end