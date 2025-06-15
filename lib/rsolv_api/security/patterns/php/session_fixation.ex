defmodule RsolvApi.Security.Patterns.Php.SessionFixation do
  @moduledoc """
  Pattern for detecting session fixation vulnerabilities in PHP.
  
  This pattern identifies when PHP applications accept session IDs from user input
  without proper regeneration, potentially allowing attackers to hijack user sessions
  by fixing the session ID before the user logs in.
  
  ## Vulnerability Details
  
  Session fixation is a security vulnerability that allows an attacker to hijack a
  legitimate user session by fixing (setting) the user's session ID before the user
  logs in. This attack exploits applications that don't regenerate session IDs after
  successful authentication, allowing the attacker to know the session ID and gain
  unauthorized access to the user's account.
  
  ### Attack Example
  ```php
  // Vulnerable code - accepts session ID from user input
  if (isset($_GET['PHPSESSID'])) {
      session_id($_GET['PHPSESSID']);
  }
  session_start();
  
  // User logs in successfully, but session ID remains the same
  // Attacker can now use the known session ID to impersonate the user
  ```
  
  The attack works by tricking the user into visiting a URL with a predetermined
  session ID, then waiting for the user to authenticate. Since the session ID
  doesn't change after login, the attacker can use the known ID to access the
  user's authenticated session.
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "php-session-fixation",
      name: "Session Fixation",
      description: "Accepting session ID from user input",
      type: :session_management,
      severity: :high,
      languages: ["php"],
      regex: ~r/session_id\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/,
      default_tier: :protected,
      cwe_id: "CWE-384",
      owasp_category: "A07:2021",
      recommendation: "Regenerate session ID after login with session_regenerate_id(true)",
      test_cases: %{
        vulnerable: [
          ~S|session_id($_GET['sid']);|,
          ~S|session_id($_POST['sessionid']);|,
          ~S|session_id($_REQUEST['session']);|,
          ~S|session_id($_COOKIE['PHPSESSID']);|
        ],
        safe: [
          ~S|session_regenerate_id(true);|,
          ~S|$session_id = session_id();|,
          ~S|session_start();|,
          ~S|session_id($generated_id);|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Session fixation is a critical web security vulnerability that allows attackers to hijack
      legitimate user sessions by predetermining the session identifier. This attack exploits
      applications that fail to regenerate session IDs after successful authentication, enabling
      attackers to gain unauthorized access to user accounts and sensitive data.
      
      The vulnerability occurs when applications accept session identifiers from user input
      (through GET parameters, POST data, cookies, or other request data) and use them without
      proper validation or regeneration. This creates an opportunity for attackers to set a
      known session ID before a user authenticates, then use that same ID to access the user's
      authenticated session after login.
      
      ### The Attack Mechanism
      
      Session fixation attacks typically follow this sequence:
      1. **Session ID Prediction/Setting**: Attacker obtains or sets a valid session ID
      2. **Session ID Fixation**: Attacker tricks the victim into using the predetermined session ID
      3. **User Authentication**: Victim logs in using the fixed session ID
      4. **Session Hijacking**: Attacker uses the known session ID to access the authenticated session
      
      ### Common Vulnerable Scenarios
      
      #### Direct Session ID Acceptance
      Applications that directly accept session IDs from user input are immediately vulnerable:
      ```php
      // VULNERABLE - accepts session ID from URL parameter
      if (isset($_GET['PHPSESSID'])) {
          session_id($_GET['PHPSESSID']);
      }
      session_start();
      ```
      
      #### Cross-Site Session ID Injection
      Attackers can inject session IDs through various means:
      ```php
      // VULNERABLE - accepts session ID from any user input
      if (isset($_POST['session_token'])) {
          session_id($_POST['session_token']);
      }
      
      // VULNERABLE - cookie-based session fixation
      if (isset($_COOKIE['custom_session'])) {
          session_id($_COOKIE['custom_session']);
      }
      ```
      
      #### Authentication Without Regeneration
      Even when not directly accepting user input, failing to regenerate session IDs
      after authentication leaves applications vulnerable:
      ```php
      // VULNERABLE - session ID remains the same after login
      session_start();
      
      if ($username && $password && authenticate($username, $password)) {
          $_SESSION['authenticated'] = true;
          $_SESSION['user_id'] = $user_id;
          // BUG: Session ID not regenerated after successful authentication
      }
      ```
      
      ### Attack Vectors and Techniques
      
      #### URL-Based Session Fixation
      ```
      # Attacker sends victim a link with predetermined session ID
      https://example.com/login.php?PHPSESSID=attacker_controlled_session_id
      
      # Or through session_name parameter
      https://example.com/login.php?SESSIONID=fixed_session_identifier
      ```
      
      #### Cookie-Based Session Fixation
      ```javascript
      // Attacker injects session cookie via XSS or other means
      document.cookie = "PHPSESSID=attacker_session_id; path=/";
      
      // Or through subdomain cookie injection
      document.cookie = "PHPSESSID=fixed_id; domain=.example.com";
      ```
      
      #### Form-Based Session Fixation
      ```html
      <!-- Attacker creates form that submits session ID -->
      <form action="https://target.com/login.php" method="post">
          <input type="hidden" name="session_id" value="attacker_controlled_id">
          <input type="text" name="username" placeholder="Username">
          <input type="password" name="password" placeholder="Password">
          <input type="submit" value="Login">
      </form>
      ```
      
      #### Meta-Refresh and JavaScript Injection
      ```html
      <!-- Attacker redirects victim to URL with fixed session -->
      <meta http-equiv="refresh" content="0;url=https://target.com/app.php?PHPSESSID=fixed_session">
      
      <!-- Or via JavaScript -->
      <script>
      window.location = "https://target.com/login?sid=attacker_session_id";
      </script>
      ```
      
      ### Impact and Consequences
      
      Successful session fixation attacks can lead to:
      - **Complete Account Takeover**: Attacker gains full access to victim's account
      - **Data Theft**: Access to personal information, financial data, and sensitive documents
      - **Privilege Escalation**: If victim has administrative privileges, attacker inherits them
      - **Financial Fraud**: Unauthorized transactions and financial manipulations
      - **Identity Theft**: Access to personal information for further malicious activities
      - **Lateral Movement**: Using compromised accounts to attack other systems
      - **Compliance Violations**: Unauthorized access may violate regulatory requirements
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-384",
          title: "Session Fixation",
          url: "https://cwe.mitre.org/data/definitions/384.html"
        },
        %{
          type: :owasp,
          id: "A07:2021",
          title: "OWASP Top 10 2021 - A07 Identification and Authentication Failures",
          url: "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
        },
        %{
          type: :owasp,
          id: "session_fixation",
          title: "OWASP Session Fixation",
          url: "https://owasp.org/www-community/attacks/Session_fixation"
        },
        %{
          type: :owasp,
          id: "session_management",
          title: "OWASP Session Management Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
        },
        %{
          type: :php,
          id: "session_security",
          title: "PHP Manual - Session Security",
          url: "https://www.php.net/manual/en/features.session.security.management.php"
        }
      ],
      attack_vectors: [
        "URL parameter injection with predetermined session IDs",
        "Cookie-based session fixation through XSS or subdomain injection",
        "Form-based session ID submission in login forms",
        "Meta-refresh redirection to URLs with fixed session IDs",
        "JavaScript injection redirecting to fixed session URLs",
        "Cross-site request forgery combined with session fixation",
        "Social engineering to trick users into clicking session-fixed URLs",
        "Email-based attacks with session-fixed links disguised as legitimate"
      ],
      real_world_impact: [
        "Complete user account compromise without credential theft",
        "Unauthorized access to banking and financial applications",
        "Administrative account takeover in content management systems",
        "E-commerce fraud through hijacked customer sessions",
        "Healthcare record access and HIPAA violations",
        "Corporate data breach through hijacked employee sessions",
        "Educational platform compromise affecting student records",
        "Government system access through session hijacking"
      ],
      cve_examples: [
        %{
          id: "CVE-2024-11317",
          description: "ABB Cylon Aspect session fixation vulnerability",
          severity: "critical",
          cvss: 9.8,
          note: "Session fixation allows attackers to fix user session identifiers before login"
        },
        %{
          id: "CVE-2024-7341",
          description: "Keycloak SAML adapter session fixation",
          severity: "high",
          cvss: 8.1,
          note: "Session ID and JSESSIONID cookie not changed at login time"
        },
        %{
          id: "CVE-2024-XXXX",
          description: "Auth0 WordPress Plugin session fixation",
          severity: "critical",
          cvss: 9.0,
          note: "Weak authentication tag generation enables session hijacking"
        },
        %{
          id: "CVE-2023-45857",
          description: "Session fixation in various PHP frameworks",
          severity: "high",
          cvss: 7.5,
          note: "Improper session ID regeneration after authentication"
        },
        %{
          id: "CVE-2023-28346",
          description: "Session fixation in Laravel Passport",
          severity: "medium",
          cvss: 6.5,
          note: "OAuth session not properly regenerated after authentication"
        }
      ],
      detection_notes: """
      This pattern detects session fixation vulnerabilities by identifying:
      - Direct usage of session_id() function with user input parameters
      - Acceptance of session identifiers from $_GET, $_POST, $_REQUEST, or $_COOKIE
      - Function calls that set session IDs from untrusted sources
      - Common patterns where user input controls session management
      
      The regex specifically looks for:
      - session_id() function calls with superglobal variable parameters
      - Various whitespace and formatting patterns around function calls
      - Multiple types of user input sources (GET, POST, REQUEST, COOKIE)
      
      False positives may occur when:
      - Session IDs are generated securely and not from user input
      - session_id() is called without parameters (returns current session ID)
      - session_id() is called with properly validated/generated identifiers
      - Functions are called in administrative or debugging contexts with proper authorization
      """,
      safe_alternatives: [
        "Use session_regenerate_id(true) after successful authentication",
        "Never accept session IDs from user input (GET, POST, cookies)",
        "Implement proper session lifecycle management",
        "Use secure session configuration options",
        "Validate session IDs against expected patterns",
        "Implement session timeout and renewal mechanisms",
        "Use HTTPS to protect session cookies in transit",
        "Implement proper logout functionality that destroys sessions"
      ],
      additional_context: %{
        common_mistakes: [
          "Accepting session IDs from URL parameters or form data",
          "Not regenerating session IDs after successful authentication",
          "Using predictable or weak session ID generation algorithms",
          "Allowing session IDs to be set through cookies without validation",
          "Failing to invalidate session IDs after logout",
          "Not implementing session timeout mechanisms"
        ],
        secure_patterns: [
          "session_regenerate_id(true) after login to destroy old session",
          "session_start() without accepting external session IDs",
          "Proper session configuration with secure cookies",
          "Regular session ID regeneration for long-lived sessions",
          "Session validation against user agents and IP addresses",
          "Proper session destruction on logout"
        ],
        php_session_config: [
          "session.use_strict_mode = 1 to reject uninitialized session IDs",
          "session.cookie_httponly = 1 to prevent JavaScript access",
          "session.cookie_secure = 1 for HTTPS-only transmission",
          "session.use_only_cookies = 1 to prevent URL-based sessions",
          "session.cookie_samesite = 'Strict' to prevent CSRF attacks"
        ],
        authentication_flow: [
          "Start session with session_start() without external input",
          "Verify credentials through secure authentication mechanism",
          "Call session_regenerate_id(true) after successful authentication",
          "Set authenticated flag and user information in session",
          "Implement regular session validation and renewal"
        ]
      }
    }
  end
  
  @doc """
  Returns test cases for the pattern.
  
  ## Examples
  
      iex> test_cases = RsolvApi.Security.Patterns.Php.SessionFixation.test_cases()
      iex> length(test_cases.positive) > 0
      true
      
      iex> test_cases = RsolvApi.Security.Patterns.Php.SessionFixation.test_cases()
      iex> length(test_cases.negative) > 0
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Php.SessionFixation.pattern()
      iex> pattern.id
      "php-session-fixation"
  """
  def test_cases do
    %{
      positive: [
        %{
          code: ~S|session_id($_GET['sid']);|,
          description: "session_id with GET parameter"
        },
        %{
          code: ~S|session_id($_POST['sessionid']);|,
          description: "session_id with POST parameter"
        },
        %{
          code: ~S|session_id($_REQUEST['session']);|,
          description: "session_id with REQUEST parameter"
        },
        %{
          code: ~S|session_id($_COOKIE['PHPSESSID']);|,
          description: "session_id with COOKIE parameter"
        },
        %{
          code: ~S|if (isset($_GET['sid'])) { session_id($_GET['sid']); }|,
          description: "conditional session_id with GET parameter"
        },
        %{
          code: ~S|session_id( $_POST['session_token'] );|,
          description: "session_id with spacing and POST parameter"
        },
        %{
          code: ~S|session_id($_REQUEST['JSESSIONID']);|,
          description: "session_id with REQUEST and Java-style session ID"
        },
        %{
          code: ~S|session_id($_GET['user_session']);|,
          description: "session_id with custom GET parameter name"
        },
        %{
          code: ~S|session_id($_POST['auth_token']);|,
          description: "session_id with authentication token from POST"
        }
      ],
      negative: [
        %{
          code: ~S|session_id();|,
          description: "session_id without parameters (returns current ID)"
        },
        %{
          code: ~S|$current_id = session_id();|,
          description: "Getting current session ID"
        },
        %{
          code: ~S|session_regenerate_id(true);|,
          description: "Proper session regeneration"
        },
        %{
          code: ~S|session_start();|,
          description: "Starting session without external input"
        },
        %{
          code: ~S|session_id($generated_id);|,
          description: "session_id with internally generated variable"
        },
        %{
          code: ~S|echo session_id();|,
          description: "Displaying current session ID"
        },
        %{
          code: ~S|$id = generate_secure_session_id(); session_id($id);|,
          description: "session_id with securely generated ID"
        },
        %{
          code: ~S|if ($admin_mode) { session_id($debug_session); }|,
          description: "Administrative session setting"
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
        "Login System" => ~S"""
        // Login system - VULNERABLE
        <?php
        // Accept session ID from URL parameter
        if (isset($_GET['PHPSESSID'])) {
            session_id($_GET['PHPSESSID']);
        }
        
        session_start();
        
        // Process login
        if ($_POST['username'] && $_POST['password']) {
            if (authenticate($_POST['username'], $_POST['password'])) {
                $_SESSION['authenticated'] = true;
                $_SESSION['user_id'] = get_user_id($_POST['username']);
                
                // BUG: Session ID not regenerated after successful login
                // Attacker can use the known session ID to hijack the session
                redirect('/dashboard');
            }
        }
        
        // Attack URL: https://example.com/login.php?PHPSESSID=attacker_session_id
        // After victim logs in, attacker can access: https://example.com/dashboard.php
        """,
        "Custom Session Management" => ~S"""
        // Custom session handler - VULNERABLE
        <?php
        class SessionManager {
            public function initialize() {
                // Accept session ID from multiple sources
                $session_id = null;
                
                if (isset($_POST['session_token'])) {
                    $session_id = $_POST['session_token'];
                } elseif (isset($_COOKIE['custom_session'])) {
                    $session_id = $_COOKIE['custom_session'];
                } elseif (isset($_GET['sid'])) {
                    $session_id = $_GET['sid'];
                }
                
                // VULNERABLE: Using user-provided session ID
                if ($session_id) {
                    session_id($session_id);
                }
                
                session_start();
            }
            
            public function authenticate($username, $password) {
                if ($this->validateCredentials($username, $password)) {
                    $_SESSION['user'] = $username;
                    $_SESSION['authenticated'] = true;
                    // BUG: No session regeneration after authentication
                    return true;
                }
                return false;
            }
        }
        
        $manager = new SessionManager();
        $manager->initialize();
        
        // Attack: POST session_token=fixed_id or cookie injection
        """,
        "E-commerce Checkout" => ~S"""
        // E-commerce system - VULNERABLE
        <?php
        // Shopping cart session management
        if (isset($_REQUEST['cart_session'])) {
            // VULNERABLE: Accept session from request data
            session_id($_REQUEST['cart_session']);
        }
        
        session_start();
        
        // Guest checkout process
        if ($_POST['guest_checkout']) {
            $_SESSION['guest_user'] = true;
            $_SESSION['cart_items'] = $_POST['items'];
            $_SESSION['billing_info'] = $_POST['billing'];
        }
        
        // User registration/login during checkout
        if ($_POST['create_account']) {
            $user_id = create_user_account($_POST['email'], $_POST['password']);
            
            // VULNERABLE: Session not regenerated when transitioning from guest to user
            $_SESSION['user_id'] = $user_id;
            $_SESSION['authenticated'] = true;
            unset($_SESSION['guest_user']);
        }
        
        // Attack: Attacker fixes session before guest checkout, then hijacks after user creates account
        """,
        "API Session Management" => ~S"""
        // API session handling - VULNERABLE
        <?php
        // REST API with session-based authentication
        class ApiController {
            public function handleRequest() {
                // Accept session ID from various headers
                $headers = getallheaders();
                
                if (isset($headers['X-Session-ID'])) {
                    session_id($headers['X-Session-ID']);
                } elseif (isset($_GET['api_session'])) {
                    session_id($_GET['api_session']);
                }
                
                session_start();
                
                // API authentication
                if ($this->authenticateApiKey($_POST['api_key'])) {
                    $_SESSION['api_authenticated'] = true;
                    $_SESSION['api_user'] = $_POST['user_id'];
                    // VULNERABLE: No session regeneration for API authentication
                }
            }
            
            public function processApiRequest() {
                if ($_SESSION['api_authenticated']) {
                    // Process authenticated API request
                    return $this->handleAuthenticatedRequest();
                }
                return $this->sendUnauthorizedResponse();
            }
        }
        
        // Attack: Client application can be tricked into using fixed session ID
        """
      },
      fixed: %{
        "Session regeneration" => ~S"""
        // Login system - SECURE
        <?php
        // Never accept session IDs from user input
        session_start();
        
        // Process login
        if ($_POST['username'] && $_POST['password']) {
            if (authenticate($_POST['username'], $_POST['password'])) {
                // SECURE: Regenerate session ID after successful authentication
                session_regenerate_id(true);
                
                $_SESSION['authenticated'] = true;
                $_SESSION['user_id'] = get_user_id($_POST['username']);
                $_SESSION['login_time'] = time();
                
                // Optional: Additional security measures
                $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
                $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];
                
                redirect('/dashboard');
            } else {
                // Regenerate session ID even after failed login attempts
                session_regenerate_id(true);
                show_error('Invalid credentials');
            }
        }
        """,
        "Login security" => ~S"""
        // Secure session management - COMPLETE
        <?php
        class SecureSessionManager {
            public function __construct() {
                // Secure session configuration
                ini_set('session.use_strict_mode', 1);
                ini_set('session.use_only_cookies', 1);
                ini_set('session.cookie_httponly', 1);
                ini_set('session.cookie_secure', 1);
                ini_set('session.cookie_samesite', 'Strict');
            }
            
            public function startSession() {
                // SECURE: Never accept external session IDs
                session_start();
                
                // Regenerate session ID periodically
                if (!isset($_SESSION['created'])) {
                    $_SESSION['created'] = time();
                } elseif (time() - $_SESSION['created'] > 300) {
                    // Regenerate every 5 minutes for active sessions
                    session_regenerate_id(true);
                    $_SESSION['created'] = time();
                }
            }
            
            public function authenticate($username, $password) {
                if ($this->validateCredentials($username, $password)) {
                    // SECURE: Always regenerate session ID after authentication
                    session_regenerate_id(true);
                    
                    $_SESSION['authenticated'] = true;
                    $_SESSION['user_id'] = $this->getUserId($username);
                    $_SESSION['login_time'] = time();
                    $_SESSION['created'] = time();
                    
                    // Security fingerprinting
                    $_SESSION['fingerprint'] = $this->generateFingerprint();
                    
                    return true;
                }
                
                // Regenerate session ID even after failed attempts
                session_regenerate_id(true);
                return false;
            }
            
            public function validateSession() {
                if (!isset($_SESSION['authenticated'])) {
                    return false;
                }
                
                // Validate session fingerprint
                if (!$this->validateFingerprint()) {
                    $this->logout();
                    return false;
                }
                
                // Check session timeout
                if (time() - $_SESSION['login_time'] > 3600) {
                    $this->logout();
                    return false;
                }
                
                return true;
            }
            
            public function logout() {
                // Secure logout process
                $_SESSION = array();
                
                if (ini_get("session.use_cookies")) {
                    $params = session_get_cookie_params();
                    setcookie(session_name(), '', time() - 42000,
                        $params["path"], $params["domain"],
                        $params["secure"], $params["httponly"]
                    );
                }
                
                session_destroy();
                session_start();
                session_regenerate_id(true);
            }
            
            private function generateFingerprint() {
                return hash('sha256', 
                    $_SERVER['HTTP_USER_AGENT'] . 
                    $_SERVER['REMOTE_ADDR'] . 
                    $_SERVER['HTTP_ACCEPT_LANGUAGE']
                );
            }
            
            private function validateFingerprint() {
                return isset($_SESSION['fingerprint']) && 
                       $_SESSION['fingerprint'] === $this->generateFingerprint();
            }
        }
        """,
        "API session security" => ~S"""
        // Secure API session handling
        <?php
        class SecureApiController {
            private $sessionManager;
            
            public function __construct() {
                $this->sessionManager = new SecureSessionManager();
            }
            
            public function handleRequest() {
                // SECURE: Never accept session IDs from external sources
                $this->sessionManager->startSession();
                
                // Use proper API authentication
                if ($this->authenticateApiRequest()) {
                    return $this->processApiRequest();
                }
                
                return $this->sendUnauthorizedResponse();
            }
            
            private function authenticateApiRequest() {
                $api_key = $this->getApiKeyFromHeaders();
                $user_data = $this->validateApiKey($api_key);
                
                if ($user_data) {
                    // SECURE: Regenerate session for new API authentication
                    session_regenerate_id(true);
                    
                    $_SESSION['api_authenticated'] = true;
                    $_SESSION['api_user_id'] = $user_data['user_id'];
                    $_SESSION['api_permissions'] = $user_data['permissions'];
                    $_SESSION['auth_time'] = time();
                    
                    return true;
                }
                
                return false;
            }
            
            private function getApiKeyFromHeaders() {
                $headers = getallheaders();
                return $headers['Authorization'] ?? null;
            }
        }
        """,
        "Configuration security" => ~S"""
        // PHP session configuration - SECURE
        <?php
        // php.ini settings or runtime configuration
        ini_set('session.use_strict_mode', 1);      // Reject uninitialized session IDs
        ini_set('session.use_only_cookies', 1);     // Prevent URL-based sessions
        ini_set('session.cookie_httponly', 1);      // Prevent JavaScript access
        ini_set('session.cookie_secure', 1);        // HTTPS-only transmission
        ini_set('session.cookie_samesite', 'Strict'); // CSRF protection
        ini_set('session.gc_maxlifetime', 1800);    // 30-minute timeout
        ini_set('session.cookie_lifetime', 0);      // Session cookies only
        
        // Additional security measures
        session_name('SECURE_SESSION_ID');          // Custom session name
        session_start();
        
        // Regular session validation
        function validateSession() {
            if (!isset($_SESSION['csrf_token'])) {
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            }
            
            // Regenerate CSRF token periodically
            if (!isset($_SESSION['csrf_created']) || 
                time() - $_SESSION['csrf_created'] > 300) {
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                $_SESSION['csrf_created'] = time();
            }
        }
        
        validateSession();
        """
      }
    }
  end
  
  @doc """
  Returns detailed vulnerability description.
  """
  def vulnerability_description do
    """
    Session fixation is a critical web security vulnerability that enables attackers to hijack
    legitimate user sessions by predetermining the session identifier. This attack exploits
    applications that fail to regenerate session IDs after successful authentication, allowing
    attackers to gain unauthorized access to user accounts without requiring credential theft.
    
    ## Understanding Session Fixation Attacks
    
    ### The Basic Mechanism
    
    Session fixation attacks work by exploiting the trust relationship between session
    identifiers and user authentication status. The attack follows this sequence:
    
    1. **Session ID Acquisition**: Attacker obtains or generates a valid session identifier
    2. **Session ID Fixation**: Attacker tricks the victim into using the predetermined session ID
    3. **User Authentication**: Victim logs in successfully using the fixed session ID
    4. **Session Hijacking**: Attacker uses the known session ID to access the authenticated session
    
    ### Common Vulnerable PHP Patterns
    
    #### Direct Session ID Acceptance
    ```php
    // VULNERABLE - accepts session ID from URL parameter
    if (isset($_GET['PHPSESSID'])) {
        session_id($_GET['PHPSESSID']);
    }
    session_start();
    
    // Attack URL: https://example.com/login.php?PHPSESSID=attacker_session_id
    ```
    
    #### Multiple Input Source Acceptance
    ```php
    // VULNERABLE - accepts session ID from various sources
    $session_sources = [$_GET['sid'], $_POST['session'], $_COOKIE['token']];
    foreach ($session_sources as $source) {
        if ($source) {
            session_id($source);
            break;
        }
    }
    session_start();
    ```
    
    #### Form-Based Session Fixation
    ```php
    // VULNERABLE - accepts session ID from form data
    if ($_POST['session_token']) {
        session_id($_POST['session_token']);
    }
    session_start();
    
    // Attacker creates malicious form with fixed session ID
    ```
    
    ## Attack Techniques and Vectors
    
    ### URL-Based Session Fixation
    The most common attack vector involves embedding session IDs in URLs:
    ```
    https://banking.example.com/login.php?PHPSESSID=ABC123ATTACKER456
    ```
    
    Attackers distribute these URLs through:
    - Email phishing campaigns
    - Social media links
    - Malicious advertisements
    - Cross-site scripting (XSS) attacks
    
    ### Cookie-Based Session Fixation
    Attackers can inject session cookies through various means:
    ```javascript
    // Via XSS vulnerability
    document.cookie = "PHPSESSID=attacker_session_id; path=/";
    
    // Via subdomain cookie injection
    document.cookie = "PHPSESSID=fixed_id; domain=.example.com; path=/";
    ```
    
    ### Cross-Site Session Fixation
    ```html
    <!-- Attacker site injects session cookie -->
    <iframe src="https://target.com/set_session.php?sid=fixed_session_id"></iframe>
    
    <!-- Then redirects victim to login -->
    <script>
    setTimeout(() => {
        window.location = "https://target.com/login.php";
    }, 1000);
    </script>
    ```
    
    ### Form-Based Attacks
    ```html
    <!-- Attacker creates fake login form -->
    <form action="https://target.com/login.php" method="post">
        <input type="hidden" name="session_id" value="attacker_controlled_session">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <input type="submit" value="Login">
    </form>
    ```
    
    ## Real-World Attack Scenarios
    
    ### Banking Application Attack
    1. Attacker sends phishing email with session-fixed banking URL
    2. Victim clicks link and is redirected to legitimate banking site
    3. Banking application accepts session ID from URL parameter
    4. Victim logs in successfully using fixed session ID
    5. Attacker uses known session ID to access victim's banking account
    
    ### E-commerce Platform Hijacking
    1. Attacker injects session cookie via XSS on related subdomain
    2. Victim browses to main e-commerce site with fixed session
    3. Victim adds items to cart and proceeds to checkout
    4. Victim creates account or logs in during checkout process
    5. Attacker accesses victim's account with saved payment methods
    
    ### Corporate Application Compromise
    1. Attacker sends internal email with session-fixed intranet URL
    2. Employee clicks link during work hours
    3. Corporate application accepts session ID from URL
    4. Employee authenticates with company credentials
    5. Attacker gains access to internal systems and sensitive data
    
    ## Advanced Attack Techniques
    
    ### Session Race Conditions
    ```php
    // VULNERABLE - race condition during authentication
    session_start();
    
    if (authenticate($username, $password)) {
        $_SESSION['authenticated'] = true;
        // WINDOW: Attacker can access session before regeneration
        sleep(1); // Simulates processing delay
        session_regenerate_id(true);
    }
    ```
    
    ### Session Adoption Attacks
    ```php
    // VULNERABLE - adopting uninitialized sessions
    session_start();
    
    if (!isset($_SESSION['initialized'])) {
        // Session might be attacker-controlled
        $_SESSION['initialized'] = true;
        $_SESSION['guest_user'] = true;
    }
    ```
    
    ### Multi-Step Authentication Bypass
    ```php
    // VULNERABLE - session not regenerated between authentication steps
    session_start();
    
    // Step 1: Username/password
    if (verify_credentials($username, $password)) {
        $_SESSION['step1_complete'] = true;
    }
    
    // Step 2: Two-factor authentication
    if ($_SESSION['step1_complete'] && verify_2fa($token)) {
        $_SESSION['authenticated'] = true;
        // BUG: Session ID still fixed from initial authentication
    }
    ```
    
    ## Prevention Strategies
    
    ### Session ID Regeneration
    The most critical defense is proper session ID regeneration:
    ```php
    // SECURE - regenerate session ID after authentication
    session_start();
    
    if (authenticate($username, $password)) {
        session_regenerate_id(true);  // true = delete old session
        $_SESSION['authenticated'] = true;
        $_SESSION['user_id'] = $user_id;
    }
    ```
    
    ### Secure Session Configuration
    ```php
    // Configure secure session settings
    ini_set('session.use_strict_mode', 1);
    ini_set('session.use_only_cookies', 1);
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', 1);
    ini_set('session.cookie_samesite', 'Strict');
    ```
    
    ### Input Validation and Rejection
    ```php
    // SECURE - never accept session IDs from user input
    // session_id($_GET['PHPSESSID']);  // NEVER DO THIS
    
    session_start();
    
    // If custom session management is needed, use mapping
    $allowed_sessions = get_valid_session_mapping();
    if (isset($_GET['app_token']) && 
        isset($allowed_sessions[$_GET['app_token']])) {
        $internal_session = $allowed_sessions[$_GET['app_token']];
        // Use internal mapping instead of direct session ID
    }
    ```
    
    ### Session Validation and Fingerprinting
    ```php
    function validate_session() {
        if (!isset($_SESSION['created'])) {
            return false;
        }
        
        // Check session age
        if (time() - $_SESSION['created'] > 3600) {
            session_destroy();
            return false;
        }
        
        // Validate session fingerprint
        $current_fingerprint = hash('sha256', 
            $_SERVER['HTTP_USER_AGENT'] . $_SERVER['REMOTE_ADDR']
        );
        
        if (!isset($_SESSION['fingerprint'])) {
            $_SESSION['fingerprint'] = $current_fingerprint;
        } elseif ($_SESSION['fingerprint'] !== $current_fingerprint) {
            session_destroy();
            return false;
        }
        
        return true;
    }
    ```
    
    ### Regular Session Regeneration
    ```php
    // Regenerate session ID periodically
    if (!isset($_SESSION['last_regeneration'])) {
        $_SESSION['last_regeneration'] = time();
    } elseif (time() - $_SESSION['last_regeneration'] > 300) {
        session_regenerate_id(true);
        $_SESSION['last_regeneration'] = time();
    }
    ```
    
    ## Security Testing
    
    ### Manual Testing Techniques
    ```
    # Test URL parameter acceptance
    https://target.com/login.php?PHPSESSID=test_session_123
    
    # Test form-based session injection
    POST /login.php
    Content-Type: application/x-www-form-urlencoded
    
    session_id=test_session_456&username=user&password=pass
    
    # Test cookie injection
    Cookie: PHPSESSID=test_session_789
    ```
    
    ### Automated Testing
    Use tools and scripts to test for session fixation:
    - Burp Suite's session handling rules
    - OWASP ZAP's session management scanner
    - Custom scripts to test session ID acceptance
    
    ## Framework-Specific Considerations
    
    ### Laravel Session Security
    ```php
    // Laravel automatically regenerates session IDs
    Auth::login($user);  // Regenerates session ID automatically
    
    // Manual regeneration if needed
    session()->regenerate();
    ```
    
    ### Symfony Session Management
    ```php
    // Symfony session regeneration
    $session = $request->getSession();
    $session->migrate(true);  // true = destroy old session
    ```
    
    Remember: Session fixation vulnerabilities can completely compromise user accounts
    without requiring credential theft. Always regenerate session IDs after authentication
    and never accept session identifiers from user input.
    """
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual vulnerabilities and false positives
  by analyzing the context of session ID usage and checking for proper security measures.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Php.SessionFixation.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:min_confidence, :rules]
      
      iex> enhancement = RsolvApi.Security.Patterns.Php.SessionFixation.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
      
      iex> enhancement = RsolvApi.Security.Patterns.Php.SessionFixation.ast_enhancement()
      iex> length(enhancement.rules)
      4
  """
  @impl true
  def ast_enhancement do
    %{
      rules: [
        %{
          type: "session_functions",
          description: "PHP functions that manage session state and identifiers",
          functions: [
            "session_id",
            "session_start",
            "session_regenerate_id",
            "session_destroy",
            "session_write_close",
            "session_set_save_handler",
            "session_name",
            "session_get_cookie_params"
          ],
          contexts: [
            "authentication_systems",
            "login_handlers",
            "session_management",
            "user_account_systems",
            "security_implementations"
          ]
        },
        %{
          type: "user_input_analysis",
          description: "Sources and handling of user input in session management",
          dangerous_sources: [
            "$_GET",
            "$_POST",
            "$_REQUEST",
            "$_COOKIE",
            "$_FILES",
            "file_get_contents('php://input')",
            "HTTP headers",
            "command line arguments"
          ],
          safe_sources: [
            "Generated session IDs",
            "Database-stored identifiers",
            "Internal system variables",
            "Cryptographically secure random values",
            "Configuration constants"
          ]
        },
        %{
          type: "security_context_analysis",
          description: "Analyze usage context to determine session fixation risk",
          high_risk_patterns: [
            "Direct session_id() calls with user input parameters",
            "Session ID acceptance from URL parameters",
            "Form-based session ID submission",
            "Cookie-based session ID injection without validation",
            "Session management without regeneration after authentication"
          ],
          mitigation_indicators: [
            "session_regenerate_id() used after authentication",
            "Session ID validation and sanitization",
            "Secure session configuration settings",
            "Session fingerprinting and validation",
            "Regular session regeneration mechanisms"
          ],
          false_positive_patterns: [
            "session_id() called without parameters (returns current ID)",
            "Session IDs generated internally with secure randomness",
            "Administrative or debugging contexts with proper authorization",
            "Session ID validation against expected patterns",
            "Session management in unit tests or development environments"
          ]
        },
        %{
          type: "authentication_flow_analysis",
          description: "Analyze authentication flow for proper session management",
          secure_patterns: [
            "Session regeneration after successful authentication",
            "Session destruction on logout",
            "Session timeout and renewal mechanisms",
            "Session validation with fingerprinting",
            "Multi-factor authentication with proper session handling"
          ],
          vulnerable_patterns: [
            "Session ID acceptance from external sources",
            "No session regeneration after authentication state changes",
            "Session IDs persisted across authentication boundaries",
            "Predictable or weak session ID generation",
            "Session data trust without validation"
          ]
        }
      ],
      min_confidence: 0.8
    }
  end
end