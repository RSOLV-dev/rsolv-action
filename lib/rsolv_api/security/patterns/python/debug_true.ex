defmodule RsolvApi.Security.Patterns.Python.DebugTrue do
  @moduledoc """
  Pattern for detecting DEBUG = True in Python code.
  
  This is a common security misconfiguration in Django and Flask applications
  where debug mode is accidentally left enabled in production.
  """

  alias RsolvApi.Security.Pattern

  @doc """
  Returns the complete pattern for detecting DEBUG = True.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Python.DebugTrue.pattern()
      iex> pattern.id
      "python-debug-true"
      iex> pattern.severity
      :medium
      iex> pattern.type
      :information_disclosure
  """
  def pattern do
    %Pattern{
      id: "python-debug-true",
      name: "Debug Mode Enabled",
      description: "Detects when DEBUG is set to True, which can expose sensitive information in production",
      type: :information_disclosure,
      severity: :medium,
      languages: ["python"],
      regex: ~r/
        # Direct DEBUG = True assignment
        DEBUG\s*=\s*True|
        # Settings with DEBUG = True
        settings\.DEBUG\s*=\s*True|
        # Configuration dictionary with debug True
        ['"]debug['"]\s*:\s*True|
        # Environment variable defaulting to True
        os\.environ\.get\s*\(\s*['"]DEBUG['"]\s*,\s*(?:True|['"]True['"])\s*\)|
        # Config object with debug = True
        \.debug\s*=\s*True|
        # app.debug = True (Flask)
        app\.debug\s*=\s*True
      /x,
      cwe_id: "CWE-215",
      owasp_category: "A05:2021",
      recommendation: "Set DEBUG = False in production environments",
      test_cases: %{
        vulnerable: [
          "DEBUG = True",
          "settings.DEBUG = True",
          "{'debug': True}",
          "os.environ.get('DEBUG', True)",
          "app.debug = True"
        ],
        safe: [
          "DEBUG = False",
          "settings.DEBUG = False",
          "{'debug': False}",
          "DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'"
        ]
      }
    }
  end

  @doc """
  Returns test cases for the pattern.
  """
  def test_cases do
    %{
      positive: [
        """
        # Django settings
        DEBUG = True
        ALLOWED_HOSTS = []
        """,
        """
        from django.conf import settings
        settings.DEBUG = True
        """,
        """
        app_config = {
            'debug': True,
            'host': '0.0.0.0'
        }
        """,
        """
        DEBUG = os.environ.get('DEBUG', True)
        """,
        """
        # Flask app
        app.debug = True
        app.run()
        """
      ],
      negative: [
        """
        DEBUG = False
        """,
        """
        # Production settings
        DEBUG = False
        """,
        """
        DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
        """,
        """
        # Dynamic configuration based on environment
        if environment == 'development':
            debug_setting = True
        else:
            debug_setting = False
        DEBUG = debug_setting
        """
      ]
    }
  end

  @doc """
  Returns examples of vulnerable and fixed code.
  """
  def examples do
    %{
      vulnerable: %{
        "Django settings with DEBUG enabled" => """
        # settings.py
        DEBUG = True
        
        ALLOWED_HOSTS = ['*']
        
        # This exposes detailed error pages to users
        """,
        "Flask application with debug mode" => """
        from flask import Flask
        
        app = Flask(__name__)
        app.debug = True  # Exposes Werkzeug debugger
        
        if __name__ == '__main__':
            app.run(host='0.0.0.0')
        """,
        "Environment variable with unsafe default" => """
        import os
        
        # Defaults to True if DEBUG env var not set
        DEBUG = os.environ.get('DEBUG', True)
        """
      },
      fixed: %{
        "Proper Django production settings" => """
        # settings.py
        DEBUG = False
        
        ALLOWED_HOSTS = ['yourdomain.com']
        
        # Use environment variable with safe default
        DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
        """,
        "Flask with environment-based debug" => """
        from flask import Flask
        import os
        
        app = Flask(__name__)
        app.debug = os.environ.get('FLASK_ENV') == 'development'
        
        if __name__ == '__main__':
            app.run()
        """,
        "Settings split by environment" => """
        # settings/base.py
        DEBUG = False  # Default to False
        
        # settings/development.py
        from .base import *
        DEBUG = True
        
        # settings/production.py
        from .base import *
        DEBUG = False
        """
      }
    }
  end

  @doc """
  Returns references for the vulnerability.
  """
  def references do
    [
      "https://cwe.mitre.org/data/definitions/215.html",
      "https://cwe.mitre.org/data/definitions/209.html",
      "https://owasp.org/www-project-top-ten/2021/Top_10/A05_2021-Security_Misconfiguration/",
      "https://docs.djangoproject.com/en/stable/ref/settings/#debug",
      "https://flask.palletsprojects.com/en/latest/debugging/"
    ]
  end

  @doc """
  Returns detailed vulnerability description.
  """
  def vulnerability_description do
    """
    Debug mode is a feature in web frameworks that provides detailed error pages,
    stack traces, and debugging information. When enabled in production, it exposes:
    
    1. **Detailed Error Pages**: Full stack traces with code snippets
    2. **Environment Variables**: Sensitive configuration values
    3. **File Paths**: Internal directory structure
    4. **Database Queries**: SQL statements and performance data
    5. **Installed Packages**: Version information for potential exploits
    
    ## Framework-Specific Risks
    
    ### Django
    - Exposes settings including SECRET_KEY
    - Shows all registered URL patterns
    - Displays template source code
    - Lists all installed apps and middleware
    
    ### Flask
    - Enables Werkzeug interactive debugger
    - Allows code execution in stack frames
    - Shows environment variables
    - Exposes application structure
    
    ## Real-World Impact
    
    - Information disclosure for targeted attacks
    - Potential remote code execution (Flask debugger)
    - Exposure of API keys and credentials
    - Database schema revelation
    
    ## Detection in Production
    
    Debug mode can often be detected by:
    - Triggering a 404 error and checking for detailed debug page
    - Looking for debug toolbars or panels
    - Checking HTTP headers for debug indicators
    """
  end

  @doc """
  Comprehensive vulnerability metadata for debug mode enabled in Python web frameworks.
  
  This metadata documents the critical security implications of running with debug mode
  enabled in production environments, particularly for Django and Flask applications.
  """
  def vulnerability_metadata do
    %{
      description: """
      Debug mode is a development feature in Python web frameworks that provides detailed 
      error pages, stack traces, and debugging information. When accidentally left enabled 
      in production environments, it creates severe security vulnerabilities by exposing 
      sensitive internal application details to potential attackers.
      
      In Django (DEBUG = True):
      1. Exposes full stack traces with source code snippets on errors
      2. Reveals all environment variables including SECRET_KEY and API credentials
      3. Shows internal file paths and directory structure
      4. Lists all registered URL patterns and view functions
      5. Displays SQL queries with execution times
      6. Shows all installed apps, middleware, and template configurations
      7. Can expose session data and authentication tokens
      
      In Flask (app.debug = True):
      1. Enables the Werkzeug interactive debugger
      2. Allows arbitrary Python code execution through the debugger console
      3. Exposes application source code and file structure
      4. Shows environment variables and configuration
      5. Provides interactive shell access in error contexts
      
      Attackers can trigger debug pages by causing application errors (404s, 500s) and
      use the exposed information to craft targeted attacks, steal credentials, or
      achieve remote code execution through the interactive debugger.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-215",
          title: "Insertion of Sensitive Information Into Debugging Code",
          url: "https://cwe.mitre.org/data/definitions/215.html"
        },
        %{
          type: :cwe,
          id: "CWE-209",
          title: "Generation of Error Message Containing Sensitive Information",
          url: "https://cwe.mitre.org/data/definitions/209.html"
        },
        %{
          type: :owasp,
          id: "A05:2021",
          title: "OWASP Top 10 2021 - A05 Security Misconfiguration",
          url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
        },
        %{
          type: :research,
          id: "vidoc_django_rce",
          title: "Escalating debug mode in Django to RCE, SSRF, SQLi",
          url: "https://blog.vidocsecurity.com/blog/escalation-of-debug-mode-in-django/"
        },
        %{
          type: :framework_docs,
          id: "django_debug",
          title: "Django DEBUG setting documentation",
          url: "https://docs.djangoproject.com/en/stable/ref/settings/#debug"
        },
        %{
          type: :framework_docs,
          id: "flask_debug",
          title: "Flask Debugging Application Errors",
          url: "https://flask.palletsprojects.com/en/latest/debugging/"
        }
      ],
      attack_vectors: [
        "Trigger 404/500 errors to access debug pages exposing sensitive data",
        "Extract SECRET_KEY from debug output to forge session cookies",
        "Use exposed file paths for directory traversal attacks",
        "Leverage SQL query information for SQL injection",
        "Execute arbitrary Python code via Werkzeug debugger console",
        "Harvest API keys and credentials from environment variables",
        "Map application structure using exposed URL patterns",
        "Exploit exposed package versions for known vulnerabilities"
      ],
      real_world_impact: [
        "Complete application takeover through RCE in Flask debug console",
        "Mass data breach via exposed database credentials",
        "Session hijacking using exposed SECRET_KEY",
        "Privilege escalation to admin access",
        "Internal network reconnaissance via SSRF",
        "Compliance violations (GDPR, HIPAA) from data exposure",
        "Intellectual property theft from exposed source code",
        "Supply chain attacks using exposed dependencies"
      ],
      cve_examples: [
        %{
          id: "CVE-2017-12794",
          description: "Django XSS vulnerability in debug page allowing code injection",
          severity: "medium",
          cvss: 6.1,
          note: "HTML autoescaping disabled in debug page template allowing XSS"
        },
        %{
          id: "CVE-2023-5457",
          description: "Django debug mode configuration allowing information disclosure",
          severity: "high",
          cvss: 7.5,
          note: "Debug=True exposes critical information enabling further attacks"
        },
        %{
          id: "CVE-2015-5306",
          description: "OpenStack Ironic debug mode enables Flask debugger with RCE",
          severity: "critical",
          cvss: 9.8,
          note: "Debug mode exposed Werkzeug debugger allowing remote code execution"
        },
        %{
          id: "CVE-2021-30459",
          description: "Django Debug Toolbar SQL injection via SQL panel",
          severity: "high",
          cvss: 8.8,
          note: "Debug toolbar allowed SQL injection through raw_sql parameter"
        }
      ],
      detection_notes: """
      This pattern detects various forms of debug mode enablement:
      
      1. Direct DEBUG = True assignment in settings files
      2. Django settings.DEBUG = True configuration
      3. Flask app.debug = True or app.config['DEBUG'] = True
      4. Environment variable defaults that enable debug (risky patterns)
      5. Configuration dictionaries with 'debug': True
      
      The pattern is case-sensitive for DEBUG to avoid false positives.
      It specifically targets production-risky patterns while allowing
      for proper environment-based configuration.
      """,
      safe_alternatives: [
        "Always set DEBUG = False in production environments",
        "Use environment-specific settings: DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'",
        "Implement separate settings files for dev/staging/production",
        "Use proper logging instead of debug mode for production diagnostics",
        "Deploy with environment variables controlling debug state",
        "Implement custom error pages that don't expose sensitive data",
        "Use monitoring tools like Sentry instead of debug mode",
        "Regular security audits to ensure debug is disabled"
      ],
      additional_context: %{
        common_mistakes: [
          "Forgetting to disable debug before deployment",
          "Using DEBUG = True as a quick fix for production issues",
          "Setting insecure defaults like os.environ.get('DEBUG', True)",
          "Not having separate configuration for different environments",
          "Exposing debug endpoints on public-facing servers",
          "Using debug mode for logging instead of proper logging framework",
          "Committing production settings with DEBUG = True to version control"
        ],
        secure_patterns: [
          "DEBUG = False  # Always in production",
          "DEBUG = os.environ.get('DJANGO_DEBUG', 'False').lower() == 'true'",
          "if os.environ.get('ENVIRONMENT') == 'production': DEBUG = False",
          "from .base import * \nDEBUG = False  # production.py",
          "app.config.from_object('config.ProductionConfig')  # Flask",
          "Use feature flags for debugging specific issues in production",
          "Implement proper error tracking with Sentry or similar"
        ],
        framework_specific_notes: %{
          django: [
            "DEBUG = True exposes django.contrib.admin without authentication",
            "Reveals all INSTALLED_APPS including internal applications",
            "Shows raw SQL queries in django.db.connection.queries",
            "Exposes SECRET_KEY which can forge sessions",
            "Lists all URL patterns revealing API structure",
            "Debug toolbar adds additional attack surface"
          ],
          flask: [
            "Werkzeug debugger PIN can be brute-forced for RCE",
            "Interactive console allows arbitrary Python execution",
            "Exposes Jinja2 template source code",
            "Shows all registered blueprints and routes",
            "Environment variables visible including API keys",
            "Stack traces reveal internal application logic"
          ]
        },
        escalation_techniques: [
          "Use exposed SECRET_KEY to create admin session cookies",
          "Leverage file paths for local file inclusion attacks",
          "Extract database credentials for direct DB access",
          "Use package versions to find applicable CVEs",
          "Chain with other vulnerabilities for maximum impact",
          "Perform SSRF attacks using internal URLs discovered",
          "Execute system commands via Werkzeug console"
        ]
      }
    }
  end

  @doc """
  Returns AST enhancement rules for improved detection.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Python.DebugTrue.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:min_confidence, :rules]
      
      iex> enhancement = RsolvApi.Security.Patterns.Python.DebugTrue.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
      
      iex> enhancement = RsolvApi.Security.Patterns.Python.DebugTrue.ast_enhancement()
      iex> length(enhancement.rules)
      2
  """
  def ast_enhancement do
    %{
      rules: [
        %{
          type: "file_context",
          description: "Reduce severity for development/test files",
          patterns: [
            "settings/development.py",
            "settings/local.py",
            "test_settings.py",
            "dev_config.py",
            "debug.py",
            "example_settings.py"
          ],
          severity_reduction: :low
        },
        %{
          type: "code_context",
          description: "Check for conditional debug settings",
          checks: [
            "if.*environment.*development",
            "if.*ENVIRONMENT.*dev",
            "if.*settings.ENVIRONMENT"
          ]
        }
      ],
      min_confidence: 0.8
    }
  end
end