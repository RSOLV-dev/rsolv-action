defmodule RsolvApi.Security.Patterns.Django.DebugSettingsTest do
  use RsolvApi.DataCase, async: true

  alias RsolvApi.Security.Pattern
  alias RsolvApi.Security.Patterns.Django.DebugSettings

  describe "pattern/0" do
    test "returns valid pattern structure" do
      pattern = DebugSettings.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "django-debug-settings"
      assert pattern.name == "Django Debug Mode in Production"
      assert pattern.description == "Debug mode exposes sensitive information in production"
      assert pattern.type == :information_disclosure
      assert pattern.severity == :high
      assert pattern.languages == ["python"]
      assert pattern.frameworks == ["django"]
      assert pattern.default_tier == :public
      assert pattern.cwe_id == "CWE-489"
      assert pattern.owasp_category == "A05:2021"
      assert is_list(pattern.regex)
      assert Enum.all?(pattern.regex, &match?(%Regex{}, &1))
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = DebugSettings.vulnerability_metadata()
      
      assert is_map(metadata)
      assert Map.has_key?(metadata, :description)
      assert Map.has_key?(metadata, :attack_vectors)
      assert Map.has_key?(metadata, :technical_impact)
      assert Map.has_key?(metadata, :business_impact)
      assert Map.has_key?(metadata, :cve_examples)
      assert Map.has_key?(metadata, :safe_alternatives)
      assert Map.has_key?(metadata, :remediation_steps)
      assert Map.has_key?(metadata, :detection_methods)
      assert Map.has_key?(metadata, :prevention_tips)
      
      assert String.contains?(metadata.description, "debug mode")
      assert String.contains?(metadata.description, "information disclosure")
      assert String.contains?(metadata.cve_examples, "CVE-")
      assert String.contains?(metadata.safe_alternatives, "DEBUG = False")
    end
  end

  describe "ast_enhancement/0" do
    test "returns AST enhancement configuration" do
      ast = DebugSettings.ast_enhancement()
      
      assert is_map(ast)
      assert Map.has_key?(ast, :context_rules)
      assert Map.has_key?(ast, :confidence_rules)
      assert Map.has_key?(ast, :ast_rules)
      
      # Check context rules
      assert is_map(ast.context_rules)
      assert is_list(ast.context_rules.debug_settings)
      assert "DEBUG" in ast.context_rules.debug_settings
      
      # Check confidence rules
      assert is_map(ast.confidence_rules)
      assert is_map(ast.confidence_rules.adjustments)
      assert ast.confidence_rules.adjustments.explicit_debug_true == +0.9
      
      # Check AST rules
      assert is_map(ast.ast_rules)
      assert ast.ast_rules.settings_analysis.detect_debug_flags == true
    end
  end

  describe "enhanced_pattern/0" do
    test "includes AST enhancement in pattern" do
      pattern = DebugSettings.enhanced_pattern()
      
      assert %Pattern{} = pattern
      assert Map.has_key?(pattern, :ast_enhancement)
      assert pattern.ast_enhancement == DebugSettings.ast_enhancement()
    end
  end

  describe "vulnerability detection" do
    test "detects DEBUG = True" do
      vulnerable_code = """
      # settings.py
      DEBUG = True
      ALLOWED_HOSTS = []
      """
      
      pattern = DebugSettings.pattern()
      
      assert Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, vulnerable_code)
      end)
    end

    test "detects DEBUG_PROPAGATE_EXCEPTIONS = True" do
      vulnerable_code = """
      # Django settings
      DEBUG_PROPAGATE_EXCEPTIONS = True
      MIDDLEWARE = [
          'django.middleware.security.SecurityMiddleware',
      ]
      """
      
      pattern = DebugSettings.pattern()
      
      assert Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, vulnerable_code)
      end)
    end

    test "detects TEMPLATE_DEBUG = True" do
      vulnerable_code = """
      TEMPLATES = [
          {
              'BACKEND': 'django.template.backends.django.DjangoTemplates',
              'DIRS': [],
              'APP_DIRS': True,
              'OPTIONS': {
                  'context_processors': [
                      'django.template.context_processors.debug',
                  ],
              },
          },
      ]
      
      TEMPLATE_DEBUG = True
      """
      
      pattern = DebugSettings.pattern()
      
      assert Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, vulnerable_code)
      end)
    end

    test "detects debug with environment variable" do
      vulnerable_code = """
      import os
      
      # This is still problematic if ENV var is True
      DEBUG = os.getenv('DJANGO_DEBUG', 'True').lower() == 'true'
      SECRET_KEY = 'django-insecure-key'
      """
      
      pattern = DebugSettings.pattern()
      
      assert Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, vulnerable_code)
      end)
    end

    test "detects various debug flag patterns" do
      vulnerable_code = """
      # Different variations of debug settings
      DEBUG = True  # Basic
      DEBUG=True    # No spaces
      DEBUG   =   True  # Extra spaces
      """
      
      pattern = DebugSettings.pattern()
      
      assert Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, vulnerable_code)
      end)
    end
  end

  describe "safe code validation" do
    test "does not flag DEBUG = False" do
      safe_code = """
      # Production settings
      DEBUG = False
      ALLOWED_HOSTS = ['mysite.com', 'www.mysite.com']
      """
      
      pattern = DebugSettings.pattern()
      
      refute Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, safe_code)
      end)
    end

    test "does not flag environment-based debug (proper pattern)" do
      safe_code = """
      import os
      
      # Proper environment-based debug setting
      DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
      # or
      DEBUG = bool(os.environ.get('DEBUG', False))
      """
      
      pattern = DebugSettings.pattern()
      
      refute Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, safe_code)
      end)
    end

    test "does not flag conditional debug settings" do
      safe_code = """
      import sys
      
      # Only enable debug for development
      if 'runserver' in sys.argv:
          DEBUG = True
      else:
          DEBUG = False
      """
      
      pattern = DebugSettings.pattern()
      
      refute Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, safe_code)
      end)
    end

    test "does not flag debug in comments" do
      safe_code = """
      # DEBUG = True  <- This is commented out
      DEBUG = False
      
      # SECURITY WARNING: don't run with debug turned on in production!
      # DEBUG = True should never be used in production
      """
      
      pattern = DebugSettings.pattern()
      
      refute Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, safe_code)
      end)
    end

    test "does not flag debug in strings or documentation" do
      safe_code = """
      DEBUG = False
      
      HELP_TEXT = '''
      To enable debug mode, set DEBUG = True in your settings.
      However, never use DEBUG = True in production.
      '''
      
      print("DEBUG = True should not be flagged in strings")
      """
      
      pattern = DebugSettings.pattern()
      
      refute Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, safe_code)
      end)
    end
  end

  describe "applies_to_file?/2" do
    test "applies to Django settings files" do
      assert DebugSettings.applies_to_file?("settings.py", ["django"])
      assert DebugSettings.applies_to_file?("local_settings.py", ["django"]) 
      assert DebugSettings.applies_to_file?("production_settings.py", ["django"])
      assert DebugSettings.applies_to_file?("config/settings/base.py", ["django"])
    end

    test "infers Django from file paths" do
      assert DebugSettings.applies_to_file?("myproject/settings.py", [])
      assert DebugSettings.applies_to_file?("config/settings/production.py", [])
      assert DebugSettings.applies_to_file?("django_project/settings/local.py", [])
    end

    test "does not apply to non-Python files" do
      refute DebugSettings.applies_to_file?("settings.json", ["django"])
      refute DebugSettings.applies_to_file?("config.yaml", ["django"])
      refute DebugSettings.applies_to_file?("debug.html", ["django"])
    end

    test "does not apply to non-settings files" do
      refute DebugSettings.applies_to_file?("views.py", ["django"])
      refute DebugSettings.applies_to_file?("models.py", ["django"])
      refute DebugSettings.applies_to_file?("urls.py", ["django"])
    end

    test "does not apply to test files" do
      refute DebugSettings.applies_to_file?("test_settings.py", ["django"])
      refute DebugSettings.applies_to_file?("tests.py", ["django"])
      refute DebugSettings.applies_to_file?("test_config.py", ["django"])
    end
  end
end