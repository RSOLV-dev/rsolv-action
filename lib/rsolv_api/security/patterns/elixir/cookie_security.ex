defmodule RsolvApi.Security.Patterns.Elixir.CookieSecurity do
  @moduledoc """
  Insecure Cookie Configuration vulnerability pattern for Elixir/Phoenix applications.

  This pattern detects cookies set without proper security flags that protect against
  session hijacking, XSS attacks, and man-in-the-middle attacks.

  ## Vulnerability Details

  Insecure cookie configuration occurs when cookies are set without essential security flags:
  - Missing `secure: true` flag allows cookies to be transmitted over unencrypted HTTP connections
  - Missing `http_only: true` flag allows client-side JavaScript to access cookies
  - Missing `same_site` attribute enables CSRF attacks and session leakage across sites
  - Sensitive session and authentication cookies require all three flags for proper security

  ## Technical Impact

  Security risks through:
  - Session hijacking via man-in-the-middle attacks on unencrypted connections
  - XSS attacks gaining access to session cookies through client-side JavaScript
  - Cross-site request forgery (CSRF) attacks exploiting missing SameSite protection
  - Cookie theft through network interception and malicious scripts

  ## Examples

  Vulnerable patterns:
  ```elixir
  # VULNERABLE - No security flags set
  put_resp_cookie(conn, "session_token", token)
  
  # VULNERABLE - Only partial security flags
  put_resp_cookie(conn, "auth_cookie", auth, secure: true)
  
  # VULNERABLE - Missing http_only and same_site
  put_resp_cookie(conn, "user_session", session, secure: true, max_age: 3600)
  
  # VULNERABLE - Insecure flag values
  put_resp_cookie(conn, "csrf_token", csrf, secure: false, http_only: true)
  ```

  Safe alternatives:
  ```elixir
  # SAFE - All required security flags present
  put_resp_cookie(conn, "session_token", token,
    secure: true,
    http_only: true,
    same_site: "Strict"
  )
  
  # SAFE - Lax SameSite for broader compatibility
  put_resp_cookie(conn, "auth_cookie", auth,
    secure: true,
    http_only: true,
    same_site: "Lax"
  )
  
  # SAFE - Using Plug.Conn module
  Plug.Conn.put_resp_cookie(conn, "user_session", session,
    secure: true,
    http_only: true,
    same_site: "Strict",
    max_age: 3600
  )
  ```

  ## Attack Scenarios

  1. **Session Hijacking**: Attackers intercept cookies transmitted over HTTP due to missing 
     `secure` flag, then use stolen session tokens to impersonate users

  2. **XSS Cookie Theft**: Malicious JavaScript in XSS attacks accesses session cookies 
     due to missing `http_only` flag, enabling account takeover

  3. **CSRF Attacks**: Missing `same_site` protection allows attackers to include cookies 
     in cross-site requests, enabling unauthorized actions

  ## References

  - CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
  - OWASP Top 10 2021 - A05: Security Misconfiguration  
  - OWASP Session Management Cheat Sheet
  - Phoenix Security Guidelines
  """

  use RsolvApi.Security.Patterns.PatternBase

  @impl true
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "elixir-cookie-security",
      name: "Insecure Cookie Configuration",
      description: "Cookies without proper security flags are vulnerable to interception, XSS attacks, and CSRF",
      type: :session_management,
      severity: :medium,
      languages: ["elixir"],
      frameworks: ["phoenix"],
      regex: [
        # Basic insecure pattern: put_resp_cookie with sensitive cookies - no options (3 params only) - exclude comments
        ~r/^(?!\s*#).*put_resp_cookie\s*\(\s*[^,]+\s*,\s*"(?:session|auth|csrf|login|token|user)[^"]*"\s*,\s*[^,)]+\s*\)\s*$/m,
        
        # Pipeline syntax for put_resp_cookie without options - exclude comments
        ~r/^(?!\s*#).*\|>\s*put_resp_cookie\s*\(\s*"(?:session|auth|csrf|login|token|user)[^"]*"\s*,\s*[^,)]+\s*\)\s*$/m,
        
        # put_resp_cookie with 4+ params that has incomplete security (doesn't have all 3 flags)
        ~r/^(?!\s*#).*put_resp_cookie\s*\(\s*[^,]+\s*,\s*"(?:session|auth|csrf|login|token|user|data)[^"]*"\s*,\s*[^,)]+\s*,[^)]*\)(?=.*\))(?!.*secure:\s*true.*http_only:\s*true.*same_site:\s*"(?:Strict|Lax|None)")/ms
      ],
      default_tier: :public,
      cwe_id: "CWE-614",
      owasp_category: "A05:2021",
      recommendation: "Always set secure: true, http_only: true, and same_site flags for cookies containing sensitive data",
      test_cases: %{
        vulnerable: [
          ~S|put_resp_cookie(conn, "session", value)|,
          ~S|put_resp_cookie(conn, "auth_token", token, secure: true)|,
          ~S|put_resp_cookie(conn, "csrf", csrf, http_only: true)|,
          "conn |> put_resp_cookie(\"user_session\", session)"
        ],
        safe: [
          ~S|put_resp_cookie(conn, "session", value, secure: true, http_only: true, same_site: "Strict")|,
          ~S|put_resp_cookie(conn, "theme", "dark")|,
          ~S|put_resp_cookie(conn, "language", "en")|,
          ~S|Plug.Conn.put_resp_cookie(conn, "auth", token, secure: true, http_only: true, same_site: "Lax")|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      attack_vectors: """
      1. Session hijacking via man-in-the-middle attacks on HTTP connections due to missing secure flag
      2. XSS attacks accessing session cookies through JavaScript due to missing http_only flag  
      3. CSRF attacks exploiting missing same_site protection for cross-origin requests
      4. Network interception of cookies transmitted over unencrypted connections
      """,
      business_impact: """
      Medium: Insecure cookie configuration can result in:
      - Account takeover and unauthorized access to user data and administrative functions
      - Data breaches through session hijacking and credential theft
      - Regulatory compliance violations related to data protection and privacy
      - Customer trust erosion due to security incidents and privacy concerns
      - Financial losses from fraudulent transactions using hijacked sessions
      """,
      technical_impact: """
      Medium: Cookie security vulnerabilities enable:
      - Session hijacking through cookie theft and replay attacks
      - Cross-site request forgery bypassing authentication mechanisms
      - XSS exploitation with access to authentication tokens and session data
      - Man-in-the-middle attacks capturing sensitive cookie values
      - Privilege escalation through stolen administrative session cookies
      """,
      likelihood: "High: Common oversight in web application development, especially during rapid development cycles",
      cve_examples: [
        "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
        "CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag", 
        "CVE-2020-26945: Cookie without secure flag vulnerability",
        "OWASP Top 10 A05:2021 - Security Misconfiguration"
      ],
      compliance_standards: [
        "OWASP Top 10 2021 - A05: Security Misconfiguration",
        "NIST Cybersecurity Framework - PR.AC: Access Control",
        "ISO 27001 - A.13.1: Network security management",
        "PCI DSS - Requirement 4: Encrypt transmission of cardholder data"
      ],
      remediation_steps: """
      1. Add secure: true flag to all cookies containing sensitive data
      2. Set http_only: true to prevent JavaScript access to authentication cookies
      3. Configure same_site attribute ("Strict", "Lax", or "None" with secure) based on requirements
      4. Review all put_resp_cookie calls for proper security flag configuration
      5. Implement automated testing to verify cookie security settings
      6. Use HTTPS enforcement to ensure secure flag effectiveness
      """,
      prevention_tips: """
      1. Always include all three security flags (secure, http_only, same_site) for sensitive cookies
      2. Use secure: true for all cookies in production HTTPS environments
      3. Set http_only: true for authentication and session cookies to prevent XSS access
      4. Choose appropriate same_site values: "Strict" for maximum protection, "Lax" for compatibility
      5. Implement cookie security linting rules in development workflows
      6. Use Phoenix session configuration for automatic secure cookie settings
      """,
      detection_methods: """
      1. Static code analysis scanning for put_resp_cookie calls without security flags
      2. Dynamic testing with security scanners checking cookie attributes
      3. Browser developer tools inspection of Set-Cookie headers
      4. Automated penetration testing focusing on session management
      5. Code reviews specifically examining cookie configuration patterns
      """,
      safe_alternatives: """
      1. Complete security flags: secure: true, http_only: true, same_site: "Strict"
      2. Phoenix session configuration with automatic secure cookie settings
      3. Middleware for enforcing cookie security policies across the application
      4. Cookie security helper functions with default secure configurations
      5. Environment-based cookie configuration for development vs production
      6. Using Phoenix.Controller.put_session for automatic session cookie security
      """
    }
  end

  @impl true  
  def ast_enhancement do
    %{
      min_confidence: 0.7,
      context_rules: %{
        sensitive_cookie_names: [
          "session",
          "auth",
          "csrf",
          "login",
          "token",
          "user",
          "authentication",
          "authorization"
        ],
        non_sensitive_cookie_names: [
          "theme",
          "language",
          "timezone",
          "preferences",
          "locale",
          "display"
        ],
        required_security_flags: [
          "secure",
          "http_only",
          "same_site"
        ],
        acceptable_same_site_values: [
          "Strict",
          "Lax", 
          "None"
        ]
      },
      confidence_rules: %{
        base: 0.7,
        adjustments: %{
          sensitive_cookie_name_bonus: 0.2,
          non_sensitive_cookie_penalty: -0.8,
          all_flags_present_penalty: -1.0,
          partial_flags_bonus: 0.1,
          no_flags_bonus: 0.2
        }
      },
      ast_rules: %{
        node_type: "cookie_security_analysis",
        cookie_analysis: %{
          check_cookie_calls: true,
          cookie_functions: ["put_resp_cookie", "Plug.Conn.put_resp_cookie"],
          check_cookie_names: true,
          check_security_flags: true
        },
        security_flags_analysis: %{
          check_secure_flag: true,
          check_http_only_flag: true,
          check_same_site_flag: true,
          require_all_flags_for_sensitive: true,
          acceptable_same_site_values: ["Strict", "Lax", "None"]
        },
        context_analysis: %{
          distinguish_sensitive_cookies: true,
          check_flag_values: true,
          check_multi_line_calls: true,
          context_radius: 3
        }
      }
    }
  end
end