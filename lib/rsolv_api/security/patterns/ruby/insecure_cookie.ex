defmodule RsolvApi.Security.Patterns.Ruby.InsecureCookie do
  @moduledoc """
  Detects Insecure Cookie Settings in Ruby applications.
  
  Cookies used for session management or authentication must be configured with proper
  security flags to prevent attacks like session hijacking, cross-site scripting (XSS),
  and cross-site request forgery (CSRF). This pattern detects cookies that are missing
  critical security attributes: secure, httponly, and samesite.
  
  ## Vulnerability Details
  
  Ruby on Rails applications commonly use cookies for session management. Without proper
  security flags, these cookies are vulnerable to various attacks:
  - Missing 'secure' flag: Cookies can be transmitted over unencrypted HTTP
  - Missing 'httponly' flag: Cookies can be accessed by client-side JavaScript (XSS)
  - Missing 'samesite' flag: Cookies can be sent in cross-site requests (CSRF)
  
  ### Attack Example
  ```ruby
  # Vulnerable - No security flags
  cookies[:auth_token] = token
  
  # Vulnerable - Missing critical flags
  cookies[:session] = { value: session_id, expires: 1.day.from_now }
  
  # Vulnerable - Explicitly disabled security
  cookies[:remember_me] = { value: user_id, httponly: false }
  
  # Secure - All security flags set
  cookies[:auth_token] = {
    value: token,
    secure: true,        # HTTPS only
    httponly: true,      # No JavaScript access
    same_site: :strict,  # CSRF protection
    expires: 1.hour.from_now
  }
  ```
  
  ### Real-World Impact
  - Session hijacking through network sniffing (missing secure flag)
  - XSS attacks stealing authentication cookies (missing httponly)
  - CSRF attacks using authenticated cookies (missing samesite)
  - Persistent attacks through long-lived cookies without security
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @doc """
  Returns the Insecure Cookie pattern for Ruby applications.
  
  Detects cookies that are set without proper security flags, making them
  vulnerable to various attacks including session hijacking, XSS, and CSRF.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.InsecureCookie.pattern()
      iex> pattern.id
      "ruby-insecure-cookie"
      
      iex> pattern = RsolvApi.Security.Patterns.Ruby.InsecureCookie.pattern()
      iex> pattern.severity
      :medium
      
      iex> pattern = RsolvApi.Security.Patterns.Ruby.InsecureCookie.pattern()
      iex> vulnerable = "cookies[:auth_token] = token"
      iex> Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable))
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Ruby.InsecureCookie.pattern()
      iex> safe = "cookies[:auth] = { value: token, secure: true, httponly: true, same_site: :strict }"
      iex> Enum.any?(pattern.regex, &Regex.match?(&1, safe))
      false
  """
  @impl true
  def pattern do
    %Pattern{
      id: "ruby-insecure-cookie",
      name: "Insecure Cookie Settings",
      description: "Detects cookies without proper security flags (secure, httponly, samesite)",
      type: :session_management,
      severity: :medium,
      languages: ["ruby"],
      regex: [
        # Direct cookie assignment without options hash
        ~r/cookies\[:\w+\]\s*=\s*[^{\s]+(?:\s|$)/,
        ~r/cookies\[['"][^'"]+['"]\]\s*=\s*[^{\s]+(?:\s|$)/,
        
        # Cookies with httponly: false
        ~r/cookies.*\bhttponly:\s*false/,
        
        # Cookies with secure: false
        ~r/cookies.*\bsecure:\s*false/,
        
        # Cookies with options hash but missing all three security flags
        ~r/cookies\[.+?\]\s*=\s*\{(?!.*\b(?:secure|httponly|same_site))[^}]+\}/,
        
        # Cookies with options hash missing secure flag
        ~r/cookies\[.+?\]\s*=\s*\{(?!.*\bsecure\b)(?=.*\bvalue\b)[^}]+\}/,
        
        # Cookies with options hash missing httponly flag
        ~r/cookies\[.+?\]\s*=\s*\{(?!.*\bhttponly\b)(?=.*\bvalue\b)[^}]+\}/,
        
        # Cookies with options hash missing same_site flag
        ~r/cookies\[.+?\]\s*=\s*\{(?!.*\bsame_site\b)(?=.*\bvalue\b)[^}]+\}/,
        
        # Permanent cookies without security flags (direct assignment)
        ~r/cookies\.permanent\[.+?\]\s*=\s*[^{\s]+(?:\s|$)/,
        ~r/cookies\.permanent\.(?:signed|encrypted)\[.+?\]\s*=\s*[^{\s]+(?:\s|$)/,
        
        # response.set_cookie without security flags
        ~r/response\.set_cookie\s*\(\s*['"][^'"]+['"]\s*,\s*[^{]/
      ],
      default_tier: :ai,
      cwe_id: "CWE-614",
      owasp_category: "A05:2021",
      recommendation: "Always set secure: true, httponly: true, and same_site: :strict or :lax for sensitive cookies",
      test_cases: %{
        vulnerable: [
          "cookies[:auth_token] = token",
          "cookies[:session] = { value: session_id, httponly: false }",
          "cookies[:user_data] = { value: data, secure: false }",
          "cookies.permanent[:remember_me] = user_id"
        ],
        safe: [
          "cookies[:auth_token] = { value: token, secure: true, httponly: true, same_site: :strict }",
          "cookies[:session] = { value: session_id, secure: true, httponly: true, same_site: :lax }",
          "# Comment about cookies[:auth_token]"
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Insecure cookie settings leave web applications vulnerable to various attacks. Without the 'secure' flag,
      cookies can be transmitted over unencrypted HTTP connections, allowing attackers to intercept them through
      network sniffing. Missing 'httponly' flags allow JavaScript to access cookies, enabling XSS attacks to steal
      session tokens. Absent 'samesite' attributes permit cookies to be sent in cross-site requests, facilitating
      CSRF attacks. These vulnerabilities are particularly critical for authentication and session cookies.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-614",
          title: "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
          url: "https://cwe.mitre.org/data/definitions/614.html"
        },
        %{
          type: :owasp,
          id: "A05:2021",
          title: "OWASP Top 10 2021 - Security Misconfiguration",
          url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
        },
        %{
          type: :research,
          id: "owasp_session_management",
          title: "Session Management Cheat Sheet - OWASP",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
        },
        %{
          type: :research,
          id: "rails_secure_cookies",
          title: "Securing Rails Applications - Cookie Security",
          url: "https://guides.rubyonrails.org/security.html#sessions"
        }
      ],
      attack_vectors: [
        "Network sniffing: Intercepting cookies sent over HTTP (missing secure flag)",
        "XSS cookie theft: document.cookie access (missing httponly flag)",
        "CSRF attacks: Cross-site form submissions with cookies (missing samesite)",
        "Session fixation: Setting victim's session ID through insecure cookies",
        "Subdomain takeover: Cookies accessible across subdomains without proper domain restriction",
        "Man-in-the-middle: Cookie interception on unsecured networks",
        "Browser history: Persistent cookies without proper expiration"
      ],
      real_world_impact: [
        "Session hijacking leading to account takeover",
        "Unauthorized access to user data and functionality",
        "CSRF attacks performing actions on behalf of users",
        "Data breaches through stolen authentication tokens",
        "Compliance violations (GDPR, PCI-DSS require secure cookies)"
      ],
      cve_examples: [
        %{
          id: "CVE-2025-27219",
          description: "Ruby CGI gem Cookie.parse DoS vulnerability due to improper cookie handling",
          severity: "high",
          cvss: 7.5,
          note: "Demonstrates the importance of proper cookie parsing and validation"
        },
        %{
          id: "CVE-2019-16782",
          description: "Rack session hijacking vulnerability through timing attacks on cookie values",
          severity: "medium",
          cvss: 5.9,
          note: "Session cookies without proper security can be exploited through timing attacks"
        },
        %{
          id: "CVE-2013-0155",
          description: "Rails session cookie vulnerability allowing remote code execution",
          severity: "critical",
          cvss: 9.8,
          note: "Insecure session cookie handling led to RCE in older Rails versions"
        }
      ],
      detection_notes: """
      This pattern detects common insecure cookie patterns in Ruby:
      - Direct cookie assignment without security options
      - Explicit disabling of security flags (httponly: false, secure: false)
      - Cookie options hash missing critical security attributes
      - Permanent cookies without security configuration
      - Response.set_cookie calls without security parameters
      
      The pattern focuses on identifying missing or disabled security flags that
      leave cookies vulnerable to various attacks.
      """,
      safe_alternatives: [
        "Always use options hash with security flags: cookies[:name] = { value: val, secure: true, httponly: true, same_site: :strict }",
        "Configure Rails defaults: config.force_ssl = true and config.cookies_same_site_protection = :strict",
        "Use encrypted cookies for sensitive data: cookies.encrypted[:user_id] = { value: id, secure: true, httponly: true }",
        "Set appropriate expiration: expires: 1.hour.from_now for session cookies",
        "Implement secure session management with Rails.application.config.session_store",
        "Use signed cookies when integrity is important: cookies.signed[:user_id] = { value: id, secure: true }"
      ],
      additional_context: %{
        common_mistakes: [
          "Assuming HTTPS automatically secures cookies (secure flag still needed)",
          "Not setting httponly on authentication cookies",
          "Using permanent cookies for sensitive data",
          "Forgetting samesite protection against CSRF",
          "Not configuring Rails-wide secure defaults"
        ],
        secure_patterns: [
          "Always include all three flags: secure, httponly, same_site",
          "Use Rails configuration for application-wide defaults",
          "Prefer encrypted or signed cookies for sensitive data",
          "Set appropriate expiration times",
          "Regularly rotate session secrets"
        ],
        framework_notes: %{
          rails: "Rails 6+ defaults to SameSite=Lax, but secure and httponly must be explicitly set",
          sinatra: "No default cookie security - all flags must be manually configured",
          general: "Ruby's CGI::Cookie and Rack::Response.set_cookie require explicit security configuration"
        }
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives for insecure cookie detection.

  This enhancement helps distinguish between actual vulnerabilities and properly
  configured cookies that might appear insecure in certain contexts.

  ## Examples

      iex> enhancement = RsolvApi.Security.Patterns.Ruby.InsecureCookie.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.InsecureCookie.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
      
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.InsecureCookie.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "CallExpression"
      
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.InsecureCookie.ast_enhancement()
      iex> enhancement.ast_rules.cookie_analysis.check_cookie_methods
      true
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        cookie_analysis: %{
          check_cookie_methods: true,
          cookie_methods: ["cookies", "response.set_cookie", "cookies.permanent", "cookies.signed", "cookies.encrypted"],
          check_options_hash: true,
          security_attributes: ["secure", "httponly", "same_site", "samesite"]
        },
        security_analysis: %{
          required_attributes: ["secure", "httponly", "same_site"],
          check_attribute_values: true,
          false_values: ["false", "nil", "0"],
          check_for_all_attributes: true,
          sensitive_cookie_names: ["session", "auth", "token", "csrf", "remember"]
        },
        configuration_analysis: %{
          check_rails_config: true,
          config_files: ["config/application.rb", "config/environments/*.rb"],
          secure_defaults: ["config.force_ssl", "config.cookies_same_site_protection"],
          check_initializers: true
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/fixtures/],
        check_framework_defaults: true,
        rails_config_files: ["application.rb", "production.rb"],
        check_environment_specific: true,
        safe_if_configured_globally: true,
        exclude_non_sensitive_cookies: true,
        non_sensitive_patterns: ["locale", "theme", "preferences", "analytics"]
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "missing_all_security_flags" => 0.4,
          "explicit_false_security_flag" => 0.5,
          "sensitive_cookie_name" => 0.3,
          "permanent_cookie" => 0.2,
          "has_secure_flag_only" => -0.2,
          "has_httponly_flag_only" => -0.2,
          "global_secure_config" => -0.8,
          "in_test_code" => -1.0,
          "non_sensitive_cookie" => -0.5
        }
      },
      min_confidence: 0.7
    }
  end
end