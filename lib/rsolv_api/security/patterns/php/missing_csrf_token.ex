defmodule RsolvApi.Security.Patterns.Php.MissingCsrfToken do
  @moduledoc """
  Pattern for detecting missing CSRF protection in PHP applications.
  
  This pattern identifies when PHP applications handle POST requests without
  implementing proper Cross-Site Request Forgery (CSRF) protection, potentially
  allowing attackers to perform unauthorized actions on behalf of users.
  
  ## Vulnerability Details
  
  CSRF attacks occur when a malicious website causes a user's browser to perform
  an unwanted action on a trusted site where the user is authenticated. Without
  CSRF tokens, applications cannot distinguish between legitimate requests from
  the user and forged requests from attackers.
  
  ### Attack Example
  ```php
  // Vulnerable code
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
      transferFunds($_POST['to'], $_POST['amount']);
  }
  
  // Attacker creates form on evil.com:
  // <form action="https://bank.com/transfer" method="POST">
  //   <input name="to" value="attacker">
  //   <input name="amount" value="10000">
  // </form>
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "php-missing-csrf-token",
      name: "Missing CSRF Protection",
      description: "POST request handling without CSRF token validation",
      type: :csrf,
      severity: :medium,
      languages: ["php"],
      regex: ~r/if\s*\(\s*\$_SERVER\[['"]REQUEST_METHOD['"]\]\s*===?\s*['"]POST['"]\s*\)\s*\{(?!.*csrf)/is,
      default_tier: :ai,
      cwe_id: "CWE-352",
      owasp_category: "A01:2021",
      recommendation: "Implement CSRF token validation for state-changing operations",
      test_cases: %{
        vulnerable: [
          ~s|if ($_SERVER['REQUEST_METHOD'] === 'POST') { updateProfile($_POST['email']); }|,
          ~s|if ($_SERVER['REQUEST_METHOD'] == 'POST') { deleteUser($_POST['id']); }|,
          ~s|if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    updateProfile($_POST['email']);
}|
        ],
        safe: [
          ~s|if ($_SERVER['REQUEST_METHOD'] === 'POST' && validateCSRFToken($_POST['csrf_token'])) { updateProfile($_POST['email']); }|,
          ~S"""
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('CSRF token validation failed');
    }
    updateProfile($_POST['email']);
}
"""
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Cross-Site Request Forgery (CSRF) is an attack that forces authenticated users
      to submit requests to a web application without their knowledge. When applications
      process POST requests without verifying CSRF tokens, attackers can trick users
      into performing unwanted actions like changing passwords, transferring funds,
      or modifying account settings.
      
      CSRF attacks exploit the trust that a web application has in the user's browser.
      Since browsers automatically include cookies with requests, an attacker can create
      a malicious page that submits forms to the vulnerable application, and the
      application will accept these requests as legitimate.
      
      ### How CSRF Attacks Work
      
      **Attack Flow**:
      1. User logs into bank.com and receives session cookie
      2. User visits attacker's site (evil.com) in another tab
      3. Evil.com contains hidden form targeting bank.com
      4. Form auto-submits POST request to bank.com/transfer
      5. Browser includes user's session cookie
      6. Bank processes transfer as legitimate request
      
      **Common Attack Vectors**:
      - Auto-submitting forms on malicious websites
      - Image tags with action URLs
      - XMLHttpRequest from attacker's domain
      - Clickjacking combined with CSRF
      
      ### Why CSRF Protection is Critical
      
      **State-Changing Operations at Risk**:
      - Password/email changes
      - Financial transactions
      - Permission modifications
      - Data deletion
      - Settings updates
      - Social actions (follow/unfollow, post content)
      
      **Trust Exploitation**:
      - Users trust legitimate sites
      - Browsers trust cookies
      - Applications trust authenticated sessions
      - No user interaction required for attack
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-352",
          title: "Cross-Site Request Forgery (CSRF)",
          url: "https://cwe.mitre.org/data/definitions/352.html"
        },
        %{
          type: :owasp,
          id: "A01:2021",
          title: "OWASP Top 10 2021 - A01 Broken Access Control",
          url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
        },
        %{
          type: :owasp_cheatsheet,
          id: "csrf_prevention",
          title: "OWASP CSRF Prevention Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
        },
        %{
          type: :research,
          id: "csrf_attacks",
          title: "CSRF Attack Examples and Prevention",
          url: "https://portswigger.net/web-security/csrf"
        }
      ],
      attack_vectors: [
        "Hidden form auto-submission: <body onload='document.forms[0].submit()'>",
        "Image tag GET requests: <img src='https://bank.com/transfer?amount=1000'>",
        "XMLHttpRequest with credentials: fetch(url, {credentials: 'include'})",
        "Clickjacking + CSRF combination attacks",
        "DNS rebinding to bypass same-origin policy",
        "Login CSRF to force user into attacker's account",
        "Logout CSRF to terminate user sessions"
      ],
      real_world_impact: [
        "Unauthorized financial transactions and fund transfers",
        "Account takeover through email/password changes",
        "Privilege escalation by modifying user roles",
        "Data breaches through unauthorized exports",
        "Social engineering amplification",
        "Reputation damage from actions performed in user's name",
        "Legal liability for unauthorized transactions"
      ],
      cve_examples: [
        %{
          id: "CVE-2024-39743",
          description: "phpMyAdmin CSRF vulnerability allowing database operations",
          severity: "high",
          cvss: 8.8,
          note: "Attackers could drop databases or modify data via CSRF"
        },
        %{
          id: "CVE-2023-52289",
          description: "WordPress plugin CSRF leading to privilege escalation",
          severity: "high",
          cvss: 8.8,
          note: "Add administrator accounts through forged requests"
        },
        %{
          id: "CVE-2022-44729",
          description: "Apache Airflow CSRF vulnerability in DAG operations",
          severity: "high",
          cvss: 8.8,
          note: "Trigger or delete workflows without authorization"
        },
        %{
          id: "CVE-2021-32682",
          description: "elFinder CSRF allowing arbitrary file operations",
          severity: "critical",
          cvss: 9.1,
          note: "Upload, delete, or modify files through CSRF attacks"
        }
      ],
      detection_notes: """
      This pattern detects missing CSRF protection by identifying:
      
      1. **POST Method Check**: Detects standard POST request handling patterns
         - $_SERVER['REQUEST_METHOD'] === 'POST'
         - $_SERVER['REQUEST_METHOD'] == 'POST'
         - Various quote styles and spacing
      
      2. **Missing CSRF Validation**: Uses negative lookahead to ensure no CSRF
         validation within the same code block
         - Looks for absence of 'csrf' keyword
         - Case insensitive matching
         - Multiline support with /s flag
      
      3. **Common Patterns**: Matches typical POST handling code
         - Direct POST checks
         - Nested conditionals
         - Various formatting styles
      
      The regex: if\\s*\\(\\s*\\$_SERVER\\[['"]REQUEST_METHOD['"]\\]\\s*===?\\s*['"]POST['"]\\s*\\)\\s*\\{(?!.*csrf)
      
      Note: This pattern may have false positives if CSRF protection is implemented
      differently (e.g., middleware, framework features, or different naming).
      """,
      safe_alternatives: [
        "Generate unique CSRF token per session: $_SESSION['csrf_token'] = bin2hex(random_bytes(32))",
        "Include token in forms: <input type='hidden' name='csrf_token' value='<?= $_SESSION['csrf_token'] ?>'>",
        "Validate token on POST: if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) die()",
        "Use framework CSRF protection: Laravel's @csrf, Symfony's csrf_token()",
        "Implement double-submit cookies for stateless CSRF protection",
        "Add SameSite cookie attribute: session_set_cookie_params(['samesite' => 'Strict'])",
        "Use custom request headers for AJAX: X-CSRF-Token"
      ],
      additional_context: %{
        common_mistakes: [
          "Using predictable CSRF tokens (timestamps, sequential numbers)",
          "Sharing CSRF tokens across different forms",
          "Not regenerating tokens after login",
          "Storing tokens in JavaScript accessible locations",
          "Implementing CSRF only for some endpoints",
          "Accepting tokens in GET parameters (vulnerable to leaks)",
          "Not validating token length or format"
        ],
        framework_solutions: [
          "Laravel: Automatic CSRF protection with VerifyCsrfToken middleware",
          "Symfony: Built-in CSRF protection in forms",
          "CodeIgniter: Security helper with csrf_field()",
          "Slim Framework: Slim-Csrf middleware",
          "WordPress: wp_nonce_field() and wp_verify_nonce()"
        ],
        implementation_tips: [
          "Per-request tokens are more secure than per-session",
          "Tokens should be cryptographically random",
          "Consider using HMAC for stateless CSRF tokens",
          "Implement proper error messages for failed validation",
          "Log CSRF failures for security monitoring",
          "Test with tools like OWASP ZAP or Burp Suite"
        ]
      }
    }
  end

  @doc """
  Returns test cases for the missing CSRF token pattern.
  
  ## Examples
  
      iex> test_cases = RsolvApi.Security.Patterns.Php.MissingCsrfToken.test_cases()
      iex> length(test_cases.positive)
      7
      
      iex> test_cases = RsolvApi.Security.Patterns.Php.MissingCsrfToken.test_cases()
      iex> length(test_cases.negative)
      7
  """
  @impl true  
  def test_cases do
    %{
      positive: [
        %{
          code: ~s|if ($_SERVER['REQUEST_METHOD'] === 'POST') { updateProfile($_POST['email']); }|,
          description: "Simple POST handler without CSRF check"
        },
        %{
          code: ~s|if ($_SERVER['REQUEST_METHOD'] == 'POST') { deleteUser($_POST['id']); }|,
          description: "POST with == comparison"
        },
        %{
          code: ~s|if($_SERVER["REQUEST_METHOD"]==="POST"){changePassword($_POST['password']);}|,
          description: "Compact POST handler"
        },
        %{
          code: ~s|if ( $_SERVER['REQUEST_METHOD'] === "POST" ) { transferFunds($_POST['amount']); }|,
          description: "POST with extra spacing"
        },
        %{
          code: ~s|if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $email = $_POST['email'];
    updateUser($username, $email);
}|,
          description: "Multi-line POST handler"
        },
        %{
          code: ~s|if ($_SERVER["REQUEST_METHOD"] == "POST") { /* process form */ }|,
          description: "POST with double quotes"
        },
        %{
          code: ~s|if ($_SERVER['REQUEST_METHOD'] === 'POST') { 
    // Process payment
    processPayment($_POST['card'], $_POST['amount']);
}|,
          description: "POST with sensitive operation"
        }
      ],
      negative: [
        %{
          code: ~s|if ($_SERVER['REQUEST_METHOD'] === 'POST' && validateCSRFToken($_POST['csrf_token'])) { updateProfile($_POST['email']); }|,
          description: "POST with CSRF validation function"
        },
        %{
          code: ~s|if ($_SERVER['REQUEST_METHOD'] === 'POST') { if (!$_POST['csrf']) die(); updateProfile($_POST['email']); }|,
          description: "POST with inline CSRF check"
        },
        %{
          code: ~s|if ($_SERVER['REQUEST_METHOD'] === 'POST') { verifyCsrfToken(); updateProfile($_POST['email']); }|,
          description: "POST with CSRF verification call"
        },
        %{
          code: ~s|if ($_SERVER['REQUEST_METHOD'] === 'GET') { showProfile(); }|,
          description: "GET request (no CSRF needed)"
        },
        %{
          code: ~s|$method = $_SERVER['REQUEST_METHOD'];|,
          description: "Just variable assignment"
        },
        %{
          code: ~s|// if ($_SERVER['REQUEST_METHOD'] === 'POST') { }|,
          description: "Commented out code"
        },
        %{
          code: ~S"""
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('Invalid CSRF token');
    }
    updateUser($_POST['username']);
}
""",
          description: "Multi-line with CSRF check"
        }
      ]
    }
  end

  @doc """
  Returns examples of vulnerable and fixed code.
  
  ## Examples
  
      iex> examples = RsolvApi.Security.Patterns.Php.MissingCsrfToken.examples()
      iex> Map.keys(examples)
      [:vulnerable, :fixed]
  """
  @impl true
  def examples do
    %{
      vulnerable: %{
        "Basic form handler" => """
        // VULNERABLE: No CSRF protection
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $email = $_POST['email'];
            $password = $_POST['password'];
            
            updateUserCredentials($email, $password);
            echo "Profile updated!";
        }
        
        // Attacker can forge requests to change user's password
        """,
        "Financial transaction" => """
        // VULNERABLE: Critical operation without CSRF
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $to_account = $_POST['to_account'];
            $amount = $_POST['amount'];
            
            // Transfer funds without verification!
            transferMoney($current_user, $to_account, $amount);
        }
        
        // Attacker can initiate transfers from victim's account
        """,
        "Admin action" => """
        // VULNERABLE: Privilege operation unprotected
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            if ($_POST['action'] === 'make_admin') {
                $user_id = $_POST['user_id'];
                grantAdminPrivileges($user_id);
            }
        }
        
        // Attacker can escalate privileges via CSRF
        """
      },
      fixed: %{
        "Token validation" => """
        // SECURE: CSRF token validation
        session_start();
        
        // Generate token if not exists
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            // Validate CSRF token
            if (!isset($_POST['csrf_token']) || 
                !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
                http_response_code(403);
                die('CSRF token validation failed');
            }
            
            // Process the form safely
            updateUserCredentials($_POST['email'], $_POST['password']);
        }
        
        // Include token in forms:
        // <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
        """,
        "Double submit cookie" => """
        // SECURE: Stateless CSRF protection
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $cookie_token = $_COOKIE['csrf_token'] ?? '';
            $post_token = $_POST['csrf_token'] ?? '';
            
            // Verify tokens match and are not empty
            if (empty($cookie_token) || empty($post_token) || 
                !hash_equals($cookie_token, $post_token)) {
                http_response_code(403);
                die('CSRF validation failed');
            }
            
            // Process request safely
            processPayment($_POST['amount'], $_POST['account']);
        }
        
        // Set cookie with JavaScript:
        // document.cookie = "csrf_token=" + generateToken() + "; SameSite=Strict";
        """,
        "Framework approach" => """
        // SECURE: Using a CSRF middleware class
        class CsrfMiddleware {
            public function handle($request, $next) {
                if ($request->method() === 'POST') {
                    $session_token = $_SESSION['csrf_token'] ?? '';
                    $request_token = $request->input('_token') ?? '';
                    
                    if (!$this->tokensMatch($session_token, $request_token)) {
                        throw new TokenMismatchException('CSRF token mismatch');
                    }
                }
                
                return $next($request);
            }
            
            private function tokensMatch($session, $request) {
                return !empty($session) && 
                       !empty($request) && 
                       hash_equals($session, $request);
            }
        }
        
        // Apply middleware to all state-changing routes
        """
      }
    }
  end

  @doc """
  Returns educational description of the vulnerability.
  
  ## Examples
  
      iex> desc = RsolvApi.Security.Patterns.Php.MissingCsrfToken.vulnerability_description()
      iex> desc =~ "CSRF"
      true
      
      iex> desc = RsolvApi.Security.Patterns.Php.MissingCsrfToken.vulnerability_description()
      iex> desc =~ "cross-site"
      true
      
      iex> desc = RsolvApi.Security.Patterns.Php.MissingCsrfToken.vulnerability_description()
      iex> desc =~ "token"
      true
  """
  @impl true
  def vulnerability_description do
    """
    Cross-Site Request Forgery (CSRF) vulnerabilities occur when web applications 
    process state-changing requests without verifying that the request was 
    intentionally made by the authenticated user, allowing attackers to perform 
    unauthorized actions on behalf of victims.
    
    CSRF attacks exploit the trust that a site has in a user's browser. Since 
    browsers automatically include credentials (cookies, session IDs) with every 
    request, malicious sites can trigger actions on vulnerable applications 
    without the user's knowledge or consent.
    
    ## Security Impact
    
    **Unauthorized Actions**: Attackers can perform any action the victim is 
    authorized to do, including changing passwords, making purchases, or 
    modifying settings.
    
    **Data Manipulation**: Forms can be submitted to create, update, or delete 
    data, potentially causing data loss or corruption.
    
    **Financial Loss**: Banking and e-commerce sites are particularly vulnerable, 
    with attacks potentially transferring funds or making purchases.
    
    ## Attack Scenarios
    
    1. **One-Click Attack**:
       - Victim visits attacker's page
       - Hidden form auto-submits to bank
       - Money transferred without consent
    
    2. **Social Engineering**:
       - "Click here to see a funny video"
       - Click triggers state change
       - Account compromised
    
    3. **Persistent Attack**:
       - Malicious code in forum post
       - Every viewer becomes victim
       - Mass exploitation
    
    ## Prevention
    
    Implement CSRF tokens that are unique per session or request, validate them 
    on every state-changing operation, use the SameSite cookie attribute, and 
    consider implementing additional defenses like requiring re-authentication 
    for sensitive actions.
    """
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual vulnerabilities and false positives
  by analyzing CSRF protection patterns and state-changing operations.

  ## Examples

      iex> enhancement = RsolvApi.Security.Patterns.Php.MissingCsrfToken.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:min_confidence, :rules]
      
      iex> enhancement = RsolvApi.Security.Patterns.Php.MissingCsrfToken.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
      
      iex> enhancement = RsolvApi.Security.Patterns.Php.MissingCsrfToken.ast_enhancement()
      iex> length(enhancement.rules)
      4
  """
  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.7,
      rules: [
        %{
          type: "csrf_validation",
          description: "Identify CSRF protection mechanisms",
          validation_patterns: [
            "csrf", "xsrf", "token", "nonce",
            "verify", "validate", "check_token",
            "authenticity", "_token", "form_token"
          ],
          validation_functions: [
            "csrf_token", "verify_nonce", "check_csrf",
            "validateToken", "verifyToken", "wp_verify_nonce"
          ]
        },
        %{
          type: "state_changing_operations",
          description: "Identify operations that need CSRF protection",
          operation_patterns: [
            "update", "delete", "create", "insert",
            "modify", "change", "set", "save",
            "transfer", "purchase", "subscribe"
          ],
          sensitive_operations: [
            "password", "email", "username", "role",
            "permission", "setting", "config", "admin"
          ]
        },
        %{
          type: "framework_protection",
          description: "Detect framework-specific CSRF protection",
          framework_patterns: [
            "middleware", "before_action", "csrf_exempt",
            "@csrf", "csrf_field", "form::token",
            "VerifyCsrfToken", "CsrfViewMiddleware"
          ],
          safe_frameworks: [
            "Laravel", "Symfony", "CodeIgniter",
            "Yii", "CakePHP", "Slim"
          ]
        },
        %{
          type: "request_analysis",
          description: "Analyze request handling context",
          safe_methods: ["GET", "HEAD", "OPTIONS"],
          unsafe_methods: ["POST", "PUT", "DELETE", "PATCH"],
          exclude_patterns: [
            "api", "webhook", "callback", "public",
            "test", "mock", "example"
          ]
        }
      ]
    }
  end
end