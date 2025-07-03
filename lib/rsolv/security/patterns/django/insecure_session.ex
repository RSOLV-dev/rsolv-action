defmodule Rsolv.Security.Patterns.Django.InsecureSession do
  @moduledoc """
  Django Insecure Session Configuration pattern for Django applications.
  
  This pattern detects insecure session cookie configurations in Django settings
  that can lead to session hijacking, cross-site scripting (XSS), and 
  man-in-the-middle attacks.
  
  ## Background
  
  Django provides several security-related settings for session and CSRF cookies:
  - SESSION_COOKIE_SECURE: Ensures cookies are only sent over HTTPS
  - SESSION_COOKIE_HTTPONLY: Prevents JavaScript access to session cookies
  - SESSION_COOKIE_SAMESITE: Prevents CSRF attacks by restricting cross-site requests
  - CSRF_COOKIE_SECURE: Ensures CSRF tokens are only sent over HTTPS
  - CSRF_COOKIE_HTTPONLY: Prevents JavaScript access to CSRF tokens
  - LANGUAGE_COOKIE_SECURE: Ensures language preference cookies use HTTPS
  
  ## Vulnerability Details
  
  When these settings are disabled (set to False) or misconfigured:
  1. Cookies can be intercepted over insecure HTTP connections
  2. JavaScript can access session cookies (XSS vulnerability)
  3. Cross-site requests can include cookies (CSRF vulnerability)
  4. Session hijacking becomes possible through various attack vectors
  
  ## Examples
  
      # VULNERABLE - Insecure session configuration
      SESSION_COOKIE_SECURE = False  # Sent over HTTP
      SESSION_COOKIE_HTTPONLY = False  # Accessible via JS
      CSRF_COOKIE_SECURE = False  # CSRF token over HTTP
      SESSION_COOKIE_SAMESITE = None  # No CSRF protection
      
      # SAFE - Secure configuration
      SESSION_COOKIE_SECURE = True
      SESSION_COOKIE_HTTPONLY = True
      SESSION_COOKIE_SAMESITE = 'Strict'
      CSRF_COOKIE_SECURE = True
      CSRF_COOKIE_HTTPONLY = True
      
      # SAFE - Production settings
      if not DEBUG:
          SESSION_COOKIE_SECURE = True
          CSRF_COOKIE_SECURE = True
  """
  
  use Rsolv.Security.Patterns.PatternBase
  
  @impl true
  def pattern do
    %Rsolv.Security.Pattern{
      id: "django-insecure-session",
      name: "Django Insecure Session Configuration",
      description: "Session cookies without secure flags expose sessions to interception",
      type: :session_management,
      severity: :high,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        ~r/^[^#]*SESSION_COOKIE_SECURE\s*=\s*False/m,
        ~r/^[^#]*SESSION_COOKIE_HTTPONLY\s*=\s*False/m,
        ~r/^[^#]*CSRF_COOKIE_SECURE\s*=\s*False/m,
        ~r/^[^#]*SESSION_COOKIE_SAMESITE\s*=\s*None/m,
        ~r/^[^#]*LANGUAGE_COOKIE_SECURE\s*=\s*False/m,
        ~r/^[^#]*CSRF_COOKIE_HTTPONLY\s*=\s*False/m
      ],
      cwe_id: "CWE-614",
      owasp_category: "A05:2021",
      recommendation: "Enable secure session cookies: SESSION_COOKIE_SECURE = True, SESSION_COOKIE_HTTPONLY = True, SESSION_COOKIE_SAMESITE = 'Strict'",
      test_cases: %{
        vulnerable: [
          "SESSION_COOKIE_SECURE = False",
          "SESSION_COOKIE_HTTPONLY = False",
          "CSRF_COOKIE_SECURE = False",
          "SESSION_COOKIE_SAMESITE = None"
        ],
        safe: [
          "SESSION_COOKIE_SECURE = True",
          "SESSION_COOKIE_HTTPONLY = True",
          "SESSION_COOKIE_SAMESITE = 'Strict'",
          "CSRF_COOKIE_SECURE = True"
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Insecure session cookie configuration in Django exposes applications to multiple
      attack vectors including session hijacking, cross-site scripting (XSS), and
      man-in-the-middle attacks. Django's session framework uses cookies to store
      session IDs by default, and these cookies must be properly secured.
      
      Key vulnerabilities arise when:
      
      1. **SESSION_COOKIE_SECURE = False**: Cookies are transmitted over insecure HTTP
         connections, allowing interception by network attackers.
      
      2. **SESSION_COOKIE_HTTPONLY = False**: JavaScript can access session cookies,
         enabling XSS attacks to steal session IDs.
      
      3. **SESSION_COOKIE_SAMESITE = None**: Cookies are sent with cross-site requests,
         enabling CSRF attacks.
      
      4. **CSRF_COOKIE_SECURE = False**: CSRF tokens transmitted over HTTP can be
         intercepted and replayed.
      
      5. **Missing security headers**: Without proper cookie flags, sessions are
         vulnerable to various client-side attacks.
      
      These vulnerabilities are particularly critical in production environments where
      sensitive user data and authenticated sessions must be protected.
      """,
      
      references: [
        %{
          type: :cwe,
          id: "CWE-614",
          title: "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
          url: "https://cwe.mitre.org/data/definitions/614.html"
        },
        %{
          type: :cwe,
          id: "CWE-1004",
          title: "Sensitive Cookie Without 'HttpOnly' Flag",
          url: "https://cwe.mitre.org/data/definitions/1004.html"
        },
        %{
          type: :cwe,
          id: "CWE-1275",
          title: "Sensitive Cookie with Improper SameSite Attribute",
          url: "https://cwe.mitre.org/data/definitions/1275.html"
        },
        %{
          type: :owasp,
          id: "A05:2021",
          title: "Security Misconfiguration",
          url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
        }
      ],
      
      attack_vectors: [
        "Session hijacking via network sniffing on HTTP connections",
        "Cross-site scripting (XSS) to steal session cookies via document.cookie",
        "Man-in-the-middle attacks intercepting session cookies over HTTP",
        "Cross-site request forgery (CSRF) exploiting missing SameSite attribute",
        "Session fixation attacks when session ID is exposed",
        "Cookie injection attacks through subdomain takeover",
        "Browser-based attacks accessing cookies via JavaScript",
        "Network-level attacks using ARP spoofing or DNS hijacking"
      ],
      
      real_world_impact: [
        "Account takeover allowing unauthorized access to user accounts",
        "Data breach exposing sensitive user information",
        "Financial fraud through hijacked payment sessions",
        "Privacy violations accessing personal user data",
        "Regulatory compliance failures (GDPR, CCPA, PCI DSS)",
        "Reputational damage from security incidents",
        "Legal liability from compromised user accounts",
        "Business disruption from mass account compromises"
      ],
      
      cve_examples: [
        %{
          id: "CVE-2014-0482",
          description: "Django RemoteUserMiddleware session hijacking vulnerability allowing authenticated users to hijack sessions via REMOTE_USER header manipulation",
          severity: "medium",
          cvss: 6.5,
          note: "Affected Django < 1.4.14, < 1.5.9, < 1.6.6"
        },
        %{
          id: "CVE-2015-3982",
          description: "Django session.flush() in cached_db backend doesn't properly flush sessions, allowing session hijacking through empty session keys",
          severity: "medium",
          cvss: 5.3,
          note: "Affected Django 1.8.x before 1.8.2"
        },
        %{
          id: "CVE-2020-5224",
          description: "django-user-sessions exposes session keys in session list views, enabling session takeover when combined with XSS",
          severity: "medium",
          cvss: 6.1,
          note: "Affected django-user-sessions before 1.7.1"
        },
        %{
          id: "CVE-2011-4136",
          description: "Django session modification vulnerability allowing remote attackers to modify sessions of other users",
          severity: "high",
          cvss: 7.5,
          note: "Affected Django before 1.2.7 and 1.3.x before 1.3.1"
        }
      ],
      
      detection_notes: """
      This pattern detects insecure session cookie configurations by matching Django
      settings that explicitly disable security features. It looks for:
      
      1. Explicit False values for security flags
      2. None value for SESSION_COOKIE_SAMESITE
      3. Missing or disabled HTTPONLY attributes
      4. Insecure cookie transmission settings
      
      The pattern focuses on production-critical settings that should never be
      disabled in live environments.
      """,
      
      safe_alternatives: [
        "SESSION_COOKIE_SECURE = True  # Always use HTTPS in production",
        "SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access",
        "SESSION_COOKIE_SAMESITE = 'Strict'  # Maximum CSRF protection",
        "CSRF_COOKIE_SECURE = True  # Secure CSRF tokens",
        "CSRF_COOKIE_HTTPONLY = True  # Protect CSRF tokens from XSS",
        "SECURE_SSL_REDIRECT = True  # Force HTTPS connections",
        "SESSION_COOKIE_AGE = 1209600  # 2 weeks max session",
        "SESSION_EXPIRE_AT_BROWSER_CLOSE = True  # Clear on close"
      ],
      
      additional_context: %{
        common_mistakes: [
          "Disabling secure cookies for local development and forgetting to enable in production",
          "Setting SESSION_COOKIE_HTTPONLY = False to access cookies in JavaScript",
          "Using SESSION_COOKIE_SAMESITE = None for cross-domain requirements without understanding risks",
          "Not using HTTPS in production, making secure cookies impossible",
          "Copying development settings to production environments"
        ],
        
        secure_patterns: [
          """
          # Separate settings for development and production
          if DEBUG:
              SESSION_COOKIE_SECURE = False
              CSRF_COOKIE_SECURE = False
          else:
              SESSION_COOKIE_SECURE = True
              CSRF_COOKIE_SECURE = True
              SECURE_SSL_REDIRECT = True
          """,
          """
          # Environment-based configuration
          SESSION_COOKIE_SECURE = os.environ.get('DJANGO_SECURE_COOKIES', 'True') == 'True'
          SESSION_COOKIE_HTTPONLY = True  # Always True
          SESSION_COOKIE_SAMESITE = 'Strict'
          """,
          """
          # Production security settings
          SECURE_BROWSER_XSS_FILTER = True
          SECURE_CONTENT_TYPE_NOSNIFF = True
          SESSION_COOKIE_SECURE = True
          CSRF_COOKIE_SECURE = True
          X_FRAME_OPTIONS = 'DENY'
          """
        ],
        
        framework_specific_notes: [
          "Django 3.0+ defaults SESSION_COOKIE_SAMESITE to 'Lax'",
          "Django 3.1+ supports SESSION_COOKIE_SAMESITE = 'None' with Secure requirement",
          "CSRF_COOKIE_HTTPONLY is False by default because JavaScript needs access for AJAX",
          "Use django-secure package for older Django versions",
          "Consider django-csp for Content Security Policy headers"
        ]
      }
    }
  end
  
  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.8,
      
      context_rules: %{
        cookie_settings: [
          "SESSION_COOKIE_SECURE",
          "SESSION_COOKIE_HTTPONLY",
          "SESSION_COOKIE_SAMESITE",
          "CSRF_COOKIE_SECURE",
          "CSRF_COOKIE_HTTPONLY",
          "LANGUAGE_COOKIE_SECURE",
          "SECURE_SSL_REDIRECT",
          "SESSION_EXPIRE_AT_BROWSER_CLOSE"
        ],
        
        django_settings_files: [
          "settings.py",
          "settings/base.py",
          "settings/production.py",
          "settings/development.py",
          "settings/local.py",
          "settings/staging.py",
          "conf/settings.py",
          "config/settings.py"
        ],
        
        security_indicators: [
          "DEBUG = False",
          "ALLOWED_HOSTS",
          "SECURE_",
          "production",
          "deploy"
        ],
        
        development_indicators: [
          "DEBUG = True",
          "localhost",
          "127.0.0.1",
          "development",
          "local"
        ]
      },
      
      confidence_rules: %{
        adjustments: %{
          # High confidence patterns
          explicit_false_value: +0.9,
          none_samesite_value: +0.9,
          multiple_insecure_settings: +0.95,
          production_file: +0.8,
          
          # Medium confidence
          single_setting: +0.5,
          staging_file: +0.6,
          
          # Lower confidence
          in_development_settings: -0.7,
          debug_true_nearby: -0.6,
          localhost_in_file: -0.5,
          conditional_setting: -0.4,
          
          # Context adjustments
          in_production_settings: +0.3,
          security_focused_file: +0.4,
          
          # False positive reduction
          in_comments: -1.0,
          in_test_file: -0.9,
          in_example_code: -0.8,
          environment_variable_based: -0.3
        }
      },
      
      ast_rules: %{
        settings_analysis: %{
          detect_cookie_configs: true,
          check_environment_specific: true,
          track_debug_mode: true,
          analyze_conditionals: true
        },
        
        file_analysis: %{
          identify_settings_files: true,
          detect_environment_type: true,
          check_import_structure: true,
          analyze_file_patterns: true
        },
        
        security_analysis: %{
          detect_security_blocks: true,
          check_ssl_configuration: true,
          analyze_middleware_setup: true,
          track_security_headers: true
        },
        
        context_analysis: %{
          check_surrounding_settings: true,
          detect_configuration_blocks: true,
          analyze_comment_context: true,
          track_conditional_logic: true
        }
      }
    }
  end
end
