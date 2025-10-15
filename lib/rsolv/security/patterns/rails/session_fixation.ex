defmodule Rsolv.Security.Patterns.Rails.SessionFixation do
  @moduledoc """
  Rails Session Fixation Vulnerability Detection Pattern.

  Session fixation attacks occur when an application authenticates a user without 
  regenerating the session identifier. This allows attackers to hijack authenticated 
  sessions by pre-setting session IDs.

  ## Vulnerability Details

  Session fixation is a broken authentication vulnerability where an attacker can:
  1. Obtain a valid session ID from the target application
  2. Force a victim to use that specific session ID (via social engineering or XSS)
  3. Wait for the victim to authenticate using the fixed session ID
  4. Access the application as the authenticated victim

  ### Attack Example
  ```ruby
  # Vulnerable: No session regeneration after authentication
  def login
    user = User.find_by(email: params[:email])
    if user&.authenticate(params[:password])
      session[:user_id] = user.id  # Session ID unchanged!
      redirect_to dashboard_path
    end
  ```

  ### Safe Example
  ```ruby  
  # Safe: Session regenerated before setting user data
  def login
    user = User.find_by(email: params[:email])
    if user&.authenticate(params[:password])
      reset_session  # Invalidates old session, creates new one
      session[:user_id] = user.id
      redirect_to dashboard_path
    end
  end
  ```
  """

  use Rsolv.Security.Patterns.PatternBase

  def pattern do
    %Rsolv.Security.Pattern{
      id: "rails-session-fixation",
      name: "Session Fixation Vulnerability",
      description: "Missing session regeneration after authentication allowing session fixation",
      type: :broken_authentication,
      severity: :medium,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        # Authentication methods without session reset - exclude if reset_session or session.regenerate is present
        ~r/def\s+(?:login|sign_in|authenticate|create)(?![\s\S]*(?:reset_session|session\.regenerate))[\s\S]*?session\[:(?:user_id|current_user_id|authenticated_user)\]\s*=[\s\S]*?end/,

        # Direct session assignment with user/admin identifiers (exclude commented lines and safe context)
        ~r/^(?!.*#)(?!.*(?:reset_session|session\.regenerate)).*session\[:user_id\]\s*=\s*[^#\r\n]*/,
        ~r/^(?!.*#)(?!.*(?:reset_session|session\.regenerate)).*session\[:current_user_id\]\s*=\s*[^#\r\n]*/,
        ~r/^(?!.*#)(?!.*(?:reset_session|session\.regenerate)).*session\[:authenticated_user\]\s*=\s*[^#\r\n]*/,
        ~r/^(?!.*#)(?!.*(?:reset_session|session\.regenerate)).*session\["user_id"\]\s*=\s*[^#\r\n]*/,
        ~r/^(?!.*#)(?!.*(?:reset_session|session\.regenerate)).*session\['user_id'\]\s*=\s*[^#\r\n]*/,

        # Admin/privilege escalation without session reset - exclude if reset_session or session.regenerate is present
        ~r/def\s+(?:admin_login|create)(?![\s\S]*(?:reset_session|session\.regenerate))[\s\S]*?session\[:(?:admin|is_admin|admin_user|super_user)\]\s*=\s*true/,
        ~r/^(?!.*#)(?!.*(?:reset_session|session\.regenerate)).*session\[:admin\]\s*=\s*true/,
        ~r/^(?!.*#)(?!.*(?:reset_session|session\.regenerate)).*session\[:is_admin\]\s*=\s*true/,
        ~r/^(?!.*#)(?!.*(?:reset_session|session\.regenerate)).*session\[:admin_user\]\s*=\s*true/,
        ~r/^(?!.*#)(?!.*(?:reset_session|session\.regenerate)).*session\[:super_user\]\s*=\s*true/
      ],
      cwe_id: "CWE-384",
      owasp_category: "A07:2021",
      recommendation:
        "Call Rails reset_session or session.regenerate before setting authentication session variables in Rails controllers",
      test_cases: %{
        vulnerable: [
          "def login\n  if user.authenticate(params[:password])\n    session[:user_id] = user.id\n  end\nend",
          "session[:user_id] = user.id",
          "session[:admin] = true",
          "def admin_login\n  if admin.valid_password?(params[:password])\n    session[:admin] = true\n  end\nend"
        ],
        safe: [
          "def login\n  if user.authenticate(params[:password])\n    reset_session\n    session[:user_id] = user.id\n  end\nend",
          "session[:cart_items] = []",
          "session[:theme] = 'dark'"
        ]
      }
    }
  end

  def vulnerability_metadata do
    %{
      description: """
      Session Fixation vulnerability in Rails applications occurs when user 
      authentication does not regenerate the session identifier. This vulnerability 
      allows attackers to hijack authenticated sessions by forcing victims to use 
      pre-determined session IDs. The attack is particularly dangerous because it 
      bypasses many traditional authentication protections by exploiting the session 
      management layer itself.
      """,
      attack_vectors: """
      1. Session ID Fixation: Attacker obtains valid session ID and forces victim to use it
      2. Social Engineering: Sending malicious links with fixed session parameters
      3. Cross-Site Scripting: JavaScript injection to set session cookies
      4. Man-in-the-Middle: Intercepting and manipulating session establishment
      5. Physical Access: Setting session cookies on shared computers
      """,
      business_impact: """
      - Complete account takeover without credential theft
      - Unauthorized access to sensitive data and functions
      - Financial fraud through hijacked authenticated sessions
      - Regulatory compliance violations (PCI DSS, GDPR, HIPAA)
      - Brand reputation damage from successful session hijacking
      - Legal liability for insufficient authentication controls
      """,
      technical_impact: """
      - Full user session hijacking and impersonation
      - Bypass of authentication mechanisms and access controls
      - Privilege escalation through admin session fixation
      - Session data manipulation and unauthorized actions
      - Persistent access even after password changes
      - Ability to perform actions on behalf of legitimate users
      """,
      likelihood:
        "Medium - Session fixation is common in custom Rails authentication implementations that don't follow security best practices",
      cve_examples: """
      CVE-2007-5380 - Session fixation vulnerability in Rails before 1.2.4
      CVE-2007-6077 - Session fixation protection mechanism bypass in Rails cgi_process.rb
      CVE-2024-47889 - Session management vulnerabilities in ActionPack
      GitHub Advisory GHSA-jwhv-rgqc-fqj5 - Rails session fixation via URL-based sessions
      """,
      compliance_standards: [
        "OWASP Top 10 2021 - A07: Identification and Authentication Failures",
        "CWE-384: Session Fixation",
        "PCI DSS 6.5.10 - Authentication and session management",
        "NIST SP 800-63B - Digital Identity Guidelines",
        "ISO 27001 A.9.4.2 - Secure log-on procedures"
      ],
      remediation_steps: """
      1. Call reset_session or session.regenerate before setting user session data
      2. Implement session regeneration in all authentication methods
      3. Use Rails built-in session protection mechanisms
      4. Validate session integrity with additional security tokens
      5. Implement session timeout and concurrent session limits
      6. Monitor and log session regeneration events
      """,
      prevention_tips: """
      - Always regenerate session IDs after successful authentication
      - Use Rails reset_session method in login controllers
      - Implement session.regenerate for session ID rotation
      - Never trust existing session data during authentication
      - Use secure session configuration (HTTPOnly, Secure flags)
      - Implement CSRF protection for additional session security
      - Consider using established authentication gems like Devise
      """,
      detection_methods: """
      - Static analysis with Brakeman to detect missing reset_session calls
      - Code review of authentication controllers and methods
      - Dynamic testing with session fixation attack tools
      - Security testing of login workflows with fixed session IDs
      - Penetration testing with manual session manipulation
      - Automated security scanning for session management flaws
      """,
      safe_alternatives: """
      # Safe Rails authentication pattern
      def login
        user = User.find_by(email: params[:email])
        if user&.authenticate(params[:password])
          reset_session  # Prevent session fixation
          session[:user_id] = user.id
          session[:last_login] = Time.current
          redirect_to dashboard_path
        else
          flash[:error] = "Invalid credentials"
          render :new
        end
      end

      # Alternative: Use session.regenerate
      def create
        if authenticate_user(params)
          session.regenerate  # Rails 7.1+ method
          session[:authenticated] = true
          redirect_to root_path
        end
      """
    }
  end

  def ast_enhancement do
    %{
      min_confidence: 0.7,
      context_rules: %{
        # Authentication-related methods that should regenerate sessions
        authentication_methods: [
          "login",
          "sign_in",
          "authenticate",
          "create",
          "admin_login",
          "log_in"
        ],

        # Session fields that indicate user authentication
        session_fields: [
          "user_id",
          "current_user_id",
          "authenticated_user",
          "admin",
          "is_admin",
          "admin_user",
          "super_user",
          "authenticated"
        ],

        # Methods that indicate proper session management
        safe_session_methods: [
          "reset_session",
          "session.regenerate",
          "regenerate"
        ],

        # Context patterns that reduce false positives
        safe_patterns: [
          # Proper session reset
          ~r/reset_session/,
          # Session regeneration  
          ~r/session\.regenerate/,
          # Shopping cart data
          ~r/session\[:cart_items\]/,
          # UI preferences
          ~r/session\[:theme\]/,
          # Language settings
          ~r/session\[:locale\]/,
          # Navigation tracking
          ~r/session\[:last_visited\]/,
          # Commented code
          ~r/#.*session\[:user_id\]/
        ]
      },
      confidence_rules: %{
        adjustments: %{
          # High confidence indicators
          missing_session_reset: +0.4,
          admin_privilege_assignment: +0.5,
          authentication_method_context: +0.3,
          direct_user_id_assignment: +0.3,

          # Lower confidence adjustments
          session_reset_present: -0.8,
          non_auth_session_data: -0.6,
          test_file_context: -0.8,
          commented_code: -1.0,

          # Context-based adjustments
          in_controller_action: +0.2,
          multiple_session_assignments: +0.2
        }
      },
      ast_rules: %{
        # Authentication flow analysis
        authentication_analysis: %{
          check_method_names: true,
          detect_session_assignments: true,
          validate_session_regeneration: true,
          check_authentication_flow: true
        },

        # Session management validation
        session_validation: %{
          check_reset_session_calls: true,
          detect_privileged_sessions: true,
          validate_session_security: true,
          check_session_lifecycle: true
        }
      }
    }
  end
end
