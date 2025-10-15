defmodule Rsolv.Security.Patterns.Django.DebugSettings do
  @moduledoc """
  Django Debug Settings pattern for Django applications.

  This pattern detects production deployments with debug mode enabled (DEBUG = True),
  which can lead to serious information disclosure vulnerabilities, exposing sensitive
  data including stack traces, environment variables, database queries, and source code.

  ## Background

  Django's DEBUG setting is intended for development only. When enabled in production,
  it exposes detailed error pages that can reveal:
  - Full stack traces with source code
  - Environment variables and settings
  - Database query details
  - File paths and application structure
  - Request/response data

  ## Vulnerability Details

  Debug mode vulnerabilities occur when:
  1. DEBUG = True is set in production settings
  2. DEBUG_PROPAGATE_EXCEPTIONS = True exposes stack traces
  3. TEMPLATE_DEBUG = True reveals template information
  4. Environment variables incorrectly default to True
  5. Conditional debug logic is flawed

  ## Examples

      # VULNERABLE - Debug enabled in production
      DEBUG = True
      ALLOWED_HOSTS = []

      # VULNERABLE - Debug propagation enabled
      DEBUG_PROPAGATE_EXCEPTIONS = True

      # VULNERABLE - Template debugging enabled
      TEMPLATE_DEBUG = True

      # SAFE - Debug disabled for production
      DEBUG = False
      ALLOWED_HOSTS = ['mysite.com']

      # SAFE - Environment-based with proper defaults
      DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'

      # SAFE - Conditional debug for development only
      if 'runserver' in sys.argv:
          DEBUG = True
      else:
          DEBUG = False
  """

  use Rsolv.Security.Patterns.PatternBase

  @impl true
  def pattern do
    %Rsolv.Security.Pattern{
      id: "django-debug-settings",
      name: "Django Debug Mode in Production",
      description: "Debug mode exposes sensitive information in production",
      type: :information_disclosure,
      severity: :high,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        # Basic DEBUG = True patterns
        ~r/^DEBUG\s*=\s*True/m,

        # DEBUG_PROPAGATE_EXCEPTIONS = True
        ~r/^DEBUG_PROPAGATE_EXCEPTIONS\s*=\s*True/m,

        # TEMPLATE_DEBUG = True (legacy Django)
        ~r/^TEMPLATE_DEBUG\s*=\s*True/m,

        # Environment variable patterns that default to True (problematic)
        ~r/DEBUG\s*=\s*os\.getenv\s*\(\s*['"][^'"]*['"],?\s*['"]True['"][^)]*\)/,

        # Various whitespace and formatting variations
        ~r/^DEBUG\s*=\s*True\s*(?:#.*)?$/m,
        ~r/^DEBUG\s*=\s*True\s*$/m
      ],
      cwe_id: "CWE-489",
      owasp_category: "A05:2021",
      recommendation:
        "Set DEBUG = False in production settings. Use environment-specific settings files.",
      test_cases: %{
        vulnerable: [
          "DEBUG = True",
          "TEMPLATE_DEBUG = True",
          "DEBUG_PROPAGATE_EXCEPTIONS = True"
        ],
        safe: [
          "DEBUG = False",
          "DEBUG = os.environ.get('DEBUG', 'False') == 'True'",
          "DEBUG = config('DEBUG', default=False, cast=bool)"
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Django debug mode information disclosure is a critical misconfiguration that occurs
      when Django applications are deployed to production with DEBUG = True. This setting
      is intended for development environments only and exposes extensive internal
      information about the application when errors occur.

      When debug mode is enabled in production, Django displays detailed error pages
      containing:

      1. **Full Stack Traces**: Complete Python tracebacks showing source code, file paths,
         and execution flow
      2. **Environment Variables**: System environment variables that may contain secrets,
         API keys, and configuration details
      3. **Settings Information**: Django settings including database configurations,
         secret keys, and other sensitive parameters
      4. **Request/Response Data**: Full HTTP request details including headers, POST data,
         and session information
      5. **Database Queries**: SQL queries executed during request processing
      6. **Template Context**: Variables and data passed to templates
      7. **Middleware Chain**: Information about middleware processing
      8. **File System Structure**: Application directory structure and file paths

      This information provides attackers with a comprehensive view of the application's
      internal workings, making it significantly easier to identify and exploit other
      vulnerabilities. The exposed data can reveal authentication mechanisms, database
      schemas, third-party integrations, and potential entry points for further attacks.
      """,
      attack_vectors: """
      1. **Information Reconnaissance**: Gathering application architecture, dependencies, and configurations
      2. **Stack Trace Analysis**: Extracting file paths, database schemas, and code logic
      3. **Secret Harvesting**: Collecting API keys, tokens, and credentials from environment variables
      4. **Database Fingerprinting**: Analyzing SQL queries to understand data models
      5. **Template Injection Discovery**: Identifying template variables and potential injection points
      6. **Session Manipulation**: Understanding session structure and authentication flows
      7. **Middleware Bypass**: Analyzing middleware chain for potential security bypasses
      8. **File System Mapping**: Understanding application structure for path traversal attacks
      9. **Third-party Service Discovery**: Identifying external integrations and API endpoints
      10. **Error-based Exploitation**: Triggering specific errors to reveal targeted information
      """,
      business_impact: """
      - Complete exposure of application architecture and security mechanisms
      - Theft of API keys, credentials, and sensitive configuration data
      - Regulatory compliance violations (GDPR, PCI-DSS, HIPAA)
      - Competitive intelligence leakage through source code exposure
      - Increased vulnerability to secondary attacks using disclosed information
      - Customer trust erosion from security misconfigurations
      - Legal liability from data protection failures
      - Financial losses from intellectual property theft
      - Reputational damage from public security incidents
      - Operational disruption from security incident response
      """,
      technical_impact: """
      - Full application source code disclosure through stack traces
      - Database schema and query pattern exposure
      - Configuration and environment variable leakage
      - Session and authentication mechanism revelation
      - File system structure and path disclosure
      - Third-party service integration details exposure
      - Middleware and security control bypass information
      - Template structure and variable context leakage
      - Error handling mechanism disclosure
      - Performance bottleneck and optimization target identification
      """,
      likelihood:
        "High - DEBUG = True is commonly left enabled during rushed deployments or inadequate production configuration",
      cve_examples: """
      CVE-2017-12794 (CVSS 6.1 MEDIUM) - Django Debug Page XSS
      - Affected Django 1.10.x before 1.10.8 and 1.11.x before 1.11.5
      - HTML autoescaping was disabled in debug error page templates
      - Allowed cross-site scripting attacks on debug pages
      - Demonstrates additional attack surface created by debug mode
      - Fixed by properly escaping all debug page content

      CVE-2023-5457 (CVSS 8.6 HIGH) - Django Debug Mode Configuration
      - CWE-1269 "Product Released in Non-Release Configuration"
      - Django web framework debug parameter set to "True" in production
      - Allows remote unauthenticated access to critical information
      - Unspecified impacts to confidentiality, integrity, and availability
      - Highlights systemic issues with debug mode in production

      CVE-2021-30459 (CVSS 7.5 HIGH) - Django Debug Toolbar SQL Injection
      - SQL injection vulnerability in django-debug-toolbar
      - Attackers could execute arbitrary SQL via debug toolbar forms
      - Specifically affects production deployments with debug tools enabled
      - Demonstrates cascade effects of debug tooling in production
      - Fixed by properly sanitizing SQL inputs in debug interfaces

      Real-world HackerOne Reports:
      - MTN Group: Information disclosure via enabled Django Debug Mode (2024)
      - Mozilla: Exposing Django Debug Panel in development environment (2023)
      - Glovo: Django debug enabled showing sensitive information (2022)
      - Multiple reports of DEBUG mode exposing API keys, database credentials
      - Common pattern: development settings accidentally deployed to production
      """,
      compliance_standards: [
        "OWASP Top 10 2021 - A05: Security Misconfiguration",
        "CWE-489: Active Debug Code",
        "CWE-1269: Product Released in Non-Release Configuration",
        "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
        "PCI DSS 6.5.8 - Improper error handling",
        "NIST SP 800-53 - SI-11 Error Handling",
        "ISO 27001 - A.12.6.1 Management of technical vulnerabilities",
        "ASVS 4.0 - V7.4 Error Handling",
        "SANS Top 25 - Improper Input Validation"
      ],
      remediation_steps: """
      1. **Immediate Production Fix**:
         ```python
         # settings.py or production_settings.py
         # SECURITY WARNING: don't run with debug turned on in production!
         DEBUG = False

         # Also ensure these are disabled
         DEBUG_PROPAGATE_EXCEPTIONS = False
         TEMPLATE_DEBUG = False

         # Set proper allowed hosts
         ALLOWED_HOSTS = ['yourdomain.com', 'www.yourdomain.com']
         ```

      2. **Environment-based Configuration**:
         ```python
         import os
         from distutils.util import strtobool

         # Method 1: Using environment variables with safe defaults
         DEBUG = bool(strtobool(os.environ.get('DEBUG', 'False')))

         # Method 2: Using django-environ
         import environ
         env = environ.Env(
             DEBUG=(bool, False)  # Default to False
         )
         DEBUG = env('DEBUG')

         # Method 3: Using python-decouple
         from decouple import config
         DEBUG = config('DEBUG', default=False, cast=bool)
         ```

      3. **Multiple Settings Files Approach**:
         ```python
         # settings/base.py
         DEBUG = False  # Default to False

         # settings/development.py
         from .base import *
         DEBUG = True
         EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

         # settings/production.py
         from .base import *
         DEBUG = False
         ALLOWED_HOSTS = ['yourdomain.com']

         # In manage.py and wsgi.py
         os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myproject.settings.production')
         ```

      4. **Conditional Debug Settings**:
         ```python
         import sys

         # Only enable debug during local development
         DEBUG = False
         if 'runserver' in sys.argv and 'localhost' in sys.argv:
             DEBUG = True

         # Or check for development indicators
         DEVELOPMENT_MODE = os.path.exists('/app/.development')
         DEBUG = DEVELOPMENT_MODE and os.environ.get('DJANGO_DEBUG', 'False').lower() == 'true'
         ```

      5. **Deployment Checklist Implementation**:
         ```python
         # Add to your CI/CD pipeline
         python manage.py check --deploy

         # This will warn about:
         # - DEBUG = True
         # - Missing ALLOWED_HOSTS
         # - Insecure SECRET_KEY
         # - Missing security middleware
         ```

      6. **Error Handling in Production**:
         ```python
         # settings/production.py
         DEBUG = False

         # Configure proper error pages
         ADMINS = [('Admin', 'admin@yourdomain.com')]
         SERVER_EMAIL = 'server@yourdomain.com'

         # Log errors instead of displaying them
         LOGGING = {
             'version': 1,
             'disable_existing_loggers': False,
             'handlers': {
                 'file': {
                     'level': 'ERROR',
                     'class': 'logging.FileHandler',
                     'filename': '/var/log/django/error.log',
                 },
                 'mail_admins': {
                     'level': 'ERROR',
                     'class': 'django.utils.log.AdminEmailHandler',
                 },
             },
             'loggers': {
                 'django': {
                     'handlers': ['file', 'mail_admins'],
                     'level': 'ERROR',
                     'propagate': True,
                 },
             },
         }
         ```

      7. **Security Middleware Configuration**:
         ```python
         # Ensure security middleware is enabled in production
         MIDDLEWARE = [
             'django.middleware.security.SecurityMiddleware',
             'django.contrib.sessions.middleware.SessionMiddleware',
             'django.middleware.common.CommonMiddleware',
             'django.middleware.csrf.CsrfViewMiddleware',
             'django.contrib.auth.middleware.AuthenticationMiddleware',
             'django.contrib.messages.middleware.MessageMiddleware',
             'django.middleware.clickjacking.XFrameOptionsMiddleware',
         ]

         # Security settings
         SECURE_BROWSER_XSS_FILTER = True
         SECURE_CONTENT_TYPE_NOSNIFF = True
         X_FRAME_OPTIONS = 'DENY'
         ```

      8. **Automated Security Checks**:
         ```bash
         # Add to your deployment pipeline
         #!/bin/bash

         # Check for debug mode
         if grep -r "DEBUG = True" . --include="*.py"; then
             echo "ERROR: DEBUG = True found in codebase"
             exit 1
         fi

         # Run Django deployment checks
         python manage.py check --deploy --fail-level ERROR

         # Security-specific checks
         python manage.py check --tag security
         ```
      """,
      prevention_tips: """
      - Always set DEBUG = False as the default in base settings
      - Use environment-specific settings files (dev/staging/prod)
      - Implement automated deployment checks for debug settings
      - Use environment variables with safe defaults
      - Run 'python manage.py check --deploy' before production deployment
      - Monitor logs for stack trace leakage in production
      - Implement proper error handling and custom error pages
      - Use infrastructure-as-code to enforce consistent configurations
      - Train development teams on secure deployment practices
      - Implement CI/CD pipelines with security checks
      """,
      detection_methods: """
      - Search for 'DEBUG = True' in settings files
      - Check for DEBUG_PROPAGATE_EXCEPTIONS = True
      - Look for TEMPLATE_DEBUG = True in legacy Django apps
      - Review environment variable configurations for unsafe defaults
      - Use Django's deployment checklist command
      - Scan for exposed Django error pages in production
      - Monitor application logs for stack trace patterns
      - Use automated security scanning tools
      - Implement infrastructure monitoring for debug mode
      - Regular security audits of deployment configurations
      """,
      safe_alternatives: """
      # 1. Environment-based Configuration with Safe Defaults
      import os
      from distutils.util import strtobool

      # Always default to False for security
      DEBUG = bool(strtobool(os.environ.get('DEBUG', 'False')))

      # 2. Multiple Settings Files Structure
      # settings/
      #   __init__.py
      #   base.py      # DEBUG = False
      #   development.py  # DEBUG = True
      #   production.py   # DEBUG = False

      # 3. Conditional Debug Based on Environment
      import sys

      DEBUG = False
      if os.environ.get('ENVIRONMENT') == 'development':
          DEBUG = True

      # 4. Using Django-environ for Type-safe Configuration
      import environ

      env = environ.Env(
          DEBUG=(bool, False),  # Type and default
          SECRET_KEY=(str, None),
          ALLOWED_HOSTS=(list, [])
      )

      # 5. Configuration Validation
      if DEBUG and 'production' in os.environ.get('ENVIRONMENT', ''):
          raise ValueError("DEBUG cannot be True in production environment")

      # 6. Proper Error Pages for Production
      # In urls.py
      from django.conf import settings
      from django.conf.urls.static import static

      if not settings.DEBUG:
          # Custom error handlers
          handler404 = 'myapp.views.custom_404'
          handler500 = 'myapp.views.custom_500'

      # 7. Security-first Settings Template
      # settings/production.py
      DEBUG = False
      ALLOWED_HOSTS = ['yourdomain.com']

      # Security settings
      SECURE_SSL_REDIRECT = True
      SECURE_BROWSER_XSS_FILTER = True
      SECURE_CONTENT_TYPE_NOSNIFF = True
      X_FRAME_OPTIONS = 'DENY'

      # Logging instead of debug pages
      LOGGING = {
          'version': 1,
          'handlers': {
              'file': {
                  'level': 'ERROR',
                  'class': 'logging.FileHandler',
                  'filename': '/var/log/django/error.log',
              },
          },
          'loggers': {
              'django': {
                  'handlers': ['file'],
                  'level': 'ERROR',
              },
          },
      }
      """
    }
  end

  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.8,
      context_rules: %{
        # Django debug-related settings
        debug_settings: [
          "DEBUG",
          "DEBUG_PROPAGATE_EXCEPTIONS",
          "TEMPLATE_DEBUG"
        ],

        # File patterns that should contain settings
        settings_files: [
          "settings.py",
          "local_settings.py",
          "production_settings.py",
          "development_settings.py",
          "base_settings.py"
        ],

        # Environment variable patterns
        env_patterns: [
          "os.environ",
          "os.getenv",
          "getenv",
          "environ.get"
        ],

        # Safe default patterns
        safe_defaults: [
          ~r/['"]False['"]/,
          ~r/False\b/,
          ~r/0\b/
        ],

        # Conditional patterns that might be safe
        conditional_patterns: [
          ~r/if\s+.*runserver/,
          ~r/if\s+.*development/,
          ~r/if\s+.*local/,
          ~r/if\s+.*debug/i
        ]
      },
      confidence_rules: %{
        adjustments: %{
          # High confidence patterns
          explicit_debug_true: +0.9,
          debug_propagate_true: +0.8,
          template_debug_true: +0.8,
          env_default_true: +0.7,

          # Medium confidence
          basic_debug_assignment: +0.6,

          # Lower confidence for safer patterns
          env_with_false_default: -0.7,
          conditional_debug: -0.8,
          commented_debug: -1.0,

          # Context adjustments
          in_settings_file: +0.3,
          in_production_config: +0.4,
          in_development_config: -0.5,

          # File location adjustments
          in_test_file: -0.9,
          in_example_code: -0.8,
          in_documentation: -0.9
        }
      },
      ast_rules: %{
        # Settings analysis
        settings_analysis: %{
          detect_debug_flags: true,
          check_assignment_context: true,
          analyze_default_values: true,
          track_environment_usage: true
        },

        # Environment analysis
        environment_analysis: %{
          check_env_defaults: true,
          detect_unsafe_patterns: true,
          analyze_fallback_values: true,
          check_type_conversion: true
        },

        # Conditional analysis
        conditional_analysis: %{
          detect_safe_conditions: true,
          check_environment_checks: true,
          analyze_development_guards: true,
          identify_runtime_conditions: true
        },

        # Django-specific
        django_analysis: %{
          check_settings_structure: true,
          analyze_deployment_config: true,
          detect_legacy_settings: true,
          check_middleware_config: true
        }
      }
    }
  end

  def applies_to_file?(file_path, frameworks) do
    # Apply to Django settings files
    is_python_file = String.ends_with?(file_path, ".py")

    # Django framework check
    frameworks_list = frameworks || []
    is_django = "django" in frameworks_list

    # Settings file patterns
    is_settings_file =
      String.contains?(file_path, "settings") ||
        (String.contains?(file_path, "config") && String.contains?(file_path, ".py"))

    # Not a test file
    not_test =
      !String.contains?(file_path, "test") &&
        !String.contains?(file_path, "spec")

    # If no frameworks specified but it looks like Django settings, include it
    inferred_django = frameworks_list == [] && is_settings_file

    is_python_file && (is_django || inferred_django) && is_settings_file && not_test
  end
end
