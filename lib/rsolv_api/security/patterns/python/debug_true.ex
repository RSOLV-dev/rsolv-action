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
      default_tier: :public,
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