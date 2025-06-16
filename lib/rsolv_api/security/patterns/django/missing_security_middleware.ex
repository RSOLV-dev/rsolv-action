defmodule RsolvApi.Security.Patterns.Django.MissingSecurityMiddleware do
  @moduledoc """
  Django Missing Security Middleware pattern for Django applications.
  
  This pattern detects when critical security middleware components are missing
  from Django's MIDDLEWARE configuration, leaving applications vulnerable to
  various attacks.
  
  ## Background
  
  Django provides several security middleware components that protect against
  common web vulnerabilities:
  
  1. **SecurityMiddleware**: Provides security enhancements including:
     - SSL redirect enforcement
     - Strict-Transport-Security header
     - X-Content-Type-Options header
     - X-Frame-Options header support
     
  2. **CsrfViewMiddleware**: Protects against Cross-Site Request Forgery attacks
  
  3. **XFrameOptionsMiddleware**: Prevents clickjacking attacks
  
  ## Vulnerability Details
  
  Missing these middleware components exposes applications to:
  - Cross-Site Request Forgery (CSRF) attacks
  - Clickjacking attacks
  - SSL stripping attacks
  - Content type sniffing attacks
  - Various header-based vulnerabilities
  
  ## Examples
  
      # VULNERABLE - Missing all security middleware
      MIDDLEWARE = [
          'django.middleware.common.CommonMiddleware',
          'django.contrib.sessions.middleware.SessionMiddleware',
      ]
      
      # VULNERABLE - Missing SecurityMiddleware
      MIDDLEWARE = [
          'django.middleware.csrf.CsrfViewMiddleware',
          'django.middleware.common.CommonMiddleware',
      ]
      
      # SAFE - Includes all security middleware
      MIDDLEWARE = [
          'django.middleware.security.SecurityMiddleware',
          'django.contrib.sessions.middleware.SessionMiddleware',
          'django.middleware.common.CommonMiddleware',
          'django.middleware.csrf.CsrfViewMiddleware',
          'django.contrib.auth.middleware.AuthenticationMiddleware',
          'django.contrib.messages.middleware.MessageMiddleware',
          'django.middleware.clickjacking.XFrameOptionsMiddleware',
      ]
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  
  @impl true
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "django-missing-security-middleware",
      name: "Django Missing Security Middleware",
      description: "Missing important security middleware in Django settings",
      type: :misconfiguration,
      severity: :high,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        # Missing SecurityMiddleware
        ~r/MIDDLEWARE(?:_CLASSES)?\s*=\s*\[(?![\s\S]*django\.middleware\.security\.SecurityMiddleware)/,
        
        # Missing CsrfViewMiddleware
        ~r/MIDDLEWARE(?:_CLASSES)?\s*=\s*\[(?![\s\S]*django\.middleware\.csrf\.CsrfViewMiddleware)/,
        
        # Missing XFrameOptionsMiddleware
        ~r/MIDDLEWARE(?:_CLASSES)?\s*=\s*\[(?![\s\S]*django\.middleware\.clickjacking\.XFrameOptionsMiddleware)/,
        
        # Empty or minimal middleware configuration
        ~r/MIDDLEWARE(?:_CLASSES)?\s*=\s*\[\s*\]/,
        ~r/MIDDLEWARE(?:_CLASSES)?\s*=\s*\[\s*['"]django\.middleware\.common\.CommonMiddleware['"]\s*\]/
      ],
      default_tier: :public,
      cwe_id: "CWE-16",
      owasp_category: "A05:2021",
      recommendation: "Add security middleware: django.middleware.security.SecurityMiddleware, django.middleware.csrf.CsrfViewMiddleware, and django.middleware.clickjacking.XFrameOptionsMiddleware",
      test_cases: %{
        vulnerable: [
          "MIDDLEWARE = ['django.middleware.common.CommonMiddleware']",
          "MIDDLEWARE = []",
          "MIDDLEWARE_CLASSES = ['django.middleware.common.CommonMiddleware']"
        ],
        safe: [
          """
          MIDDLEWARE = [
              'django.middleware.security.SecurityMiddleware',
              'django.middleware.csrf.CsrfViewMiddleware',
              'django.middleware.clickjacking.XFrameOptionsMiddleware',
          ]
          """
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Django's middleware system provides critical security features that protect
      applications from common web vulnerabilities. Missing security middleware
      leaves applications exposed to multiple attack vectors.
      
      Key security middleware components:
      
      1. **SecurityMiddleware** (django.middleware.security.SecurityMiddleware):
         - Enforces SSL/TLS connections via SECURE_SSL_REDIRECT
         - Sets Strict-Transport-Security header (HSTS)
         - Adds X-Content-Type-Options: nosniff header
         - Provides secure cookie settings
         - Prevents protocol downgrade attacks
      
      2. **CsrfViewMiddleware** (django.middleware.csrf.CsrfViewMiddleware):
         - Protects against Cross-Site Request Forgery attacks
         - Validates CSRF tokens on state-changing requests
         - Essential for form security
      
      3. **XFrameOptionsMiddleware** (django.middleware.clickjacking.XFrameOptionsMiddleware):
         - Sets X-Frame-Options header
         - Prevents clickjacking attacks
         - Controls iframe embedding
      
      Missing these middleware components creates a cascade of vulnerabilities
      that can be exploited individually or in combination for sophisticated attacks.
      """,
      
      references: [
        %{
          type: :cwe,
          id: "CWE-16",
          title: "Configuration",
          url: "https://cwe.mitre.org/data/definitions/16.html"
        },
        %{
          type: :cwe,
          id: "CWE-352",
          title: "Cross-Site Request Forgery (CSRF)",
          url: "https://cwe.mitre.org/data/definitions/352.html"
        },
        %{
          type: :cwe,
          id: "CWE-1021",
          title: "Improper Restriction of Rendered UI Layers or Frames",
          url: "https://cwe.mitre.org/data/definitions/1021.html"
        },
        %{
          type: :owasp,
          id: "A05:2021",
          title: "Security Misconfiguration",
          url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
        }
      ],
      
      attack_vectors: [
        "Cross-Site Request Forgery (CSRF) attacks via forged requests",
        "Clickjacking attacks through iframe embedding",
        "SSL stripping attacks downgrading HTTPS to HTTP",
        "Content type sniffing leading to XSS",
        "Protocol downgrade attacks",
        "Missing security headers exploitation",
        "Session hijacking through insecure cookies",
        "Man-in-the-middle attacks on unencrypted connections"
      ],
      
      real_world_impact: [
        "Unauthorized actions performed on behalf of users",
        "Account takeover through CSRF attacks",
        "Sensitive data exposure via protocol downgrade",
        "UI redressing attacks tricking users",
        "Compliance violations (PCI DSS, OWASP standards)",
        "Reputation damage from security incidents",
        "Financial losses from fraudulent transactions",
        "Legal liability from data breaches"
      ],
      
      cve_examples: [
        %{
          id: "CVE-2015-0221",
          description: "Django static file serving vulnerability allowing DoS through missing security headers",
          severity: "medium",
          cvss: 5.3,
          note: "Demonstrates importance of security middleware for static file handling"
        },
        %{
          id: "CVE-2016-2512",
          description: "Django redirect vulnerability exploitable when security headers are missing",
          severity: "medium",
          cvss: 6.1,
          note: "Shows how missing middleware can enable redirect-based attacks"
        },
        %{
          id: "CVE-2018-14574",
          description: "Django CommonMiddleware open redirect when security middleware absent",
          severity: "medium",
          cvss: 6.1,
          note: "Highlights risks of relying on CommonMiddleware without security layers"
        },
        %{
          id: "CVE-2023-46695",
          description: "Django DoS vulnerability partially mitigated by proper middleware configuration",
          severity: "medium",
          cvss: 5.3,
          note: "Recent example showing ongoing importance of security middleware"
        }
      ],
      
      detection_notes: """
      This pattern detects missing security middleware by:
      
      1. Checking for absence of SecurityMiddleware in MIDDLEWARE setting
      2. Verifying CsrfViewMiddleware is present for CSRF protection
      3. Ensuring XFrameOptionsMiddleware is configured
      4. Supporting both MIDDLEWARE (Django 1.10+) and MIDDLEWARE_CLASSES (older)
      5. Detecting empty or minimal middleware configurations
      
      The pattern uses negative lookahead assertions to identify when specific
      middleware components are missing from the configuration.
      """,
      
      safe_alternatives: [
        """
        # Complete security middleware configuration
        MIDDLEWARE = [
            'django.middleware.security.SecurityMiddleware',
            'django.contrib.sessions.middleware.SessionMiddleware',
            'django.middleware.common.CommonMiddleware',
            'django.middleware.csrf.CsrfViewMiddleware',
            'django.contrib.auth.middleware.AuthenticationMiddleware',
            'django.contrib.messages.middleware.MessageMiddleware',
            'django.middleware.clickjacking.XFrameOptionsMiddleware',
        ]
        """,
        """
        # With additional security headers
        MIDDLEWARE = [
            'django.middleware.security.SecurityMiddleware',
            'whitenoise.middleware.WhiteNoiseMiddleware',  # For static files
            'django.contrib.sessions.middleware.SessionMiddleware',
            'corsheaders.middleware.CorsMiddleware',  # CORS if needed
            'django.middleware.common.CommonMiddleware',
            'django.middleware.csrf.CsrfViewMiddleware',
            'django.contrib.auth.middleware.AuthenticationMiddleware',
            'django.contrib.messages.middleware.MessageMiddleware',
            'django.middleware.clickjacking.XFrameOptionsMiddleware',
            'csp.middleware.CSPMiddleware',  # Content Security Policy
        ]
        """,
        """
        # Configure security settings alongside middleware
        SECURE_SSL_REDIRECT = True
        SECURE_HSTS_SECONDS = 31536000
        SECURE_HSTS_INCLUDE_SUBDOMAINS = True
        SECURE_HSTS_PRELOAD = True
        SECURE_CONTENT_TYPE_NOSNIFF = True
        SECURE_BROWSER_XSS_FILTER = True
        X_FRAME_OPTIONS = 'DENY'
        """
      ],
      
      additional_context: %{
        common_mistakes: [
          "Disabling CsrfViewMiddleware for API endpoints without proper alternatives",
          "Removing SecurityMiddleware in development and forgetting to re-enable",
          "Incorrect middleware ordering affecting security features",
          "Using MIDDLEWARE_CLASSES in Django 1.10+ instead of MIDDLEWARE",
          "Conditionally including security middleware based on DEBUG setting"
        ],
        
        secure_patterns: [
          """
          # Environment-specific middleware
          MIDDLEWARE = [
              'django.middleware.security.SecurityMiddleware',
              # ... other middleware ...
          ]
          
          if not DEBUG:
              # Additional production security
              MIDDLEWARE.insert(1, 'django.middleware.gzip.GZipMiddleware')
          """,
          """
          # API-specific CSRF handling
          from django.views.decorators.csrf import csrf_exempt
          
          # Use decorators for specific views instead of removing middleware
          @csrf_exempt
          @require_api_key  # Custom authentication
          def api_endpoint(request):
              pass
          """,
          """
          # Testing middleware configuration
          def test_security_middleware_present(self):
              from django.conf import settings
              middleware = settings.MIDDLEWARE
              
              required = [
                  'django.middleware.security.SecurityMiddleware',
                  'django.middleware.csrf.CsrfViewMiddleware',
                  'django.middleware.clickjacking.XFrameOptionsMiddleware',
              ]
              
              for mw in required:
                  self.assertIn(mw, middleware)
          """
        ],
        
        framework_specific_notes: [
          "Django 1.10+ uses MIDDLEWARE setting, older versions use MIDDLEWARE_CLASSES",
          "Middleware order matters - SecurityMiddleware should be near the top",
          "Some third-party packages require specific middleware ordering",
          "Django REST Framework may require modified CSRF handling",
          "Debug toolbar middleware should only be included in development",
          "Consider django-csp for Content Security Policy headers",
          "Use django-cors-headers for CORS instead of custom middleware"
        ]
      }
    }
  end
  
  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.8,
      
      context_rules: %{
        security_middleware: [
          "django.middleware.security.SecurityMiddleware",
          "django.middleware.csrf.CsrfViewMiddleware",
          "django.middleware.clickjacking.XFrameOptionsMiddleware",
          "django.contrib.auth.middleware.AuthenticationMiddleware",
          "django.contrib.sessions.middleware.SessionMiddleware"
        ],
        
        optional_security_middleware: [
          "corsheaders.middleware.CorsMiddleware",
          "csp.middleware.CSPMiddleware",
          "django_permissions_policy.PermissionsPolicyMiddleware",
          "django_feature_policy.FeaturePolicyMiddleware"
        ],
        
        django_settings_files: [
          "settings.py",
          "settings/base.py",
          "settings/production.py",
          "settings/common.py",
          "settings/__init__.py",
          "conf/settings.py",
          "config/settings.py"
        ],
        
        middleware_indicators: [
          "MIDDLEWARE =",
          "MIDDLEWARE_CLASSES =",
          "MIDDLEWARE.append",
          "MIDDLEWARE.insert",
          "MIDDLEWARE.extend"
        ]
      },
      
      confidence_rules: %{
        adjustments: %{
          # High confidence patterns
          all_security_missing: +0.95,
          empty_middleware: +0.99,
          only_common_middleware: +0.9,
          
          # Medium confidence
          single_middleware_missing: +0.6,
          two_middleware_missing: +0.8,
          
          # Lower confidence
          in_development_settings: -0.5,
          in_test_settings: -0.8,
          debug_true_present: -0.4,
          conditional_middleware: -0.3,
          
          # Context adjustments
          in_production_settings: +0.3,
          has_security_comments: +0.2,
          
          # False positive reduction
          third_party_middleware_present: -0.2,
          custom_security_middleware: -0.4,
          api_only_project: -0.3
        }
      },
      
      ast_rules: %{
        middleware_analysis: %{
          detect_middleware_list: true,
          check_ordering: true,
          validate_completeness: true,
          analyze_conditional_inclusion: true
        },
        
        configuration_analysis: %{
          check_middleware_setting: true,
          detect_legacy_settings: true,
          analyze_imports: true,
          check_related_settings: true
        },
        
        security_analysis: %{
          identify_security_middleware: true,
          check_custom_middleware: true,
          analyze_decorators: true,
          detect_bypass_patterns: true
        },
        
        context_analysis: %{
          check_file_type: true,
          detect_environment: true,
          analyze_comments: true,
          check_django_version: true
        }
      }
    }
  end
end