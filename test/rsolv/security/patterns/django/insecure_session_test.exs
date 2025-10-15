defmodule Rsolv.Security.Patterns.Django.InsecureSessionTest do
  use ExUnit.Case

  alias Rsolv.Security.Patterns.Django.InsecureSession
  alias Rsolv.Security.Pattern

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = InsecureSession.pattern()

      assert pattern.id == "django-insecure-session"
      assert pattern.name == "Django Insecure Session Configuration"

      assert pattern.description ==
               "Session cookies without secure flags expose sessions to interception"

      assert pattern.type == :session_management
      assert pattern.severity == :high
      assert pattern.languages == ["python"]
      assert pattern.frameworks == ["django"]
      assert pattern.cwe_id == "CWE-614"
      assert pattern.owasp_category == "A05:2021"
      assert pattern.recommendation =~ "Enable secure session cookies"
    end

    test "includes all security cookie settings patterns" do
      pattern = InsecureSession.pattern()

      # SESSION_COOKIE_SECURE
      assert Enum.any?(pattern.regex, &(&1 == ~r/^[^#]*SESSION_COOKIE_SECURE\s*=\s*False/m))

      # SESSION_COOKIE_HTTPONLY
      assert Enum.any?(pattern.regex, &(&1 == ~r/^[^#]*SESSION_COOKIE_HTTPONLY\s*=\s*False/m))

      # CSRF_COOKIE_SECURE
      assert Enum.any?(pattern.regex, &(&1 == ~r/^[^#]*CSRF_COOKIE_SECURE\s*=\s*False/m))

      # SESSION_COOKIE_SAMESITE
      assert Enum.any?(pattern.regex, &(&1 == ~r/^[^#]*SESSION_COOKIE_SAMESITE\s*=\s*None/m))

      # LANGUAGE_COOKIE_SECURE
      assert Enum.any?(pattern.regex, &(&1 == ~r/^[^#]*LANGUAGE_COOKIE_SECURE\s*=\s*False/m))

      # CSRF_COOKIE_HTTPONLY
      assert Enum.any?(pattern.regex, &(&1 == ~r/^[^#]*CSRF_COOKIE_HTTPONLY\s*=\s*False/m))
    end

    test "includes test cases for vulnerable code" do
      pattern = InsecureSession.pattern()

      assert "SESSION_COOKIE_SECURE = False" in pattern.test_cases.vulnerable
      assert "SESSION_COOKIE_HTTPONLY = False" in pattern.test_cases.vulnerable
      assert "CSRF_COOKIE_SECURE = False" in pattern.test_cases.vulnerable
      assert "SESSION_COOKIE_SAMESITE = None" in pattern.test_cases.vulnerable
    end

    test "includes test cases for safe code" do
      pattern = InsecureSession.pattern()

      assert "SESSION_COOKIE_SECURE = True" in pattern.test_cases.safe
      assert "SESSION_COOKIE_HTTPONLY = True" in pattern.test_cases.safe
      assert "SESSION_COOKIE_SAMESITE = 'Strict'" in pattern.test_cases.safe
      assert "CSRF_COOKIE_SECURE = True" in pattern.test_cases.safe
    end
  end

  describe "vulnerability_metadata/0" do
    test "includes comprehensive vulnerability details" do
      metadata = InsecureSession.vulnerability_metadata()

      assert is_map(metadata)
      assert Map.has_key?(metadata, :description)
      assert Map.has_key?(metadata, :references)
      assert Map.has_key?(metadata, :attack_vectors)
      assert Map.has_key?(metadata, :real_world_impact)
      assert Map.has_key?(metadata, :cve_examples)
      assert Map.has_key?(metadata, :detection_notes)
      assert Map.has_key?(metadata, :safe_alternatives)
      assert Map.has_key?(metadata, :additional_context)
    end

    test "includes relevant CVE examples" do
      metadata = InsecureSession.vulnerability_metadata()
      cve_examples = metadata.cve_examples

      assert is_list(cve_examples)
      assert length(cve_examples) >= 3

      # Check for known Django session-related CVEs
      cve_ids = Enum.map(cve_examples, & &1.id)
      # RemoteUserMiddleware session hijacking
      assert "CVE-2014-0482" in cve_ids
      # Session flushing vulnerability
      assert "CVE-2015-3982" in cve_ids
      # django-user-sessions key exposure
      assert "CVE-2020-5224" in cve_ids
    end

    test "includes attack vectors" do
      metadata = InsecureSession.vulnerability_metadata()

      assert is_list(metadata.attack_vectors)
      assert length(metadata.attack_vectors) >= 3

      # Should include session hijacking methods
      vectors_text = Enum.join(metadata.attack_vectors, " ")
      assert vectors_text =~ ~r/session.*hijack/i
      assert vectors_text =~ ~r/man.*in.*the.*middle/i
      assert vectors_text =~ ~r/xss/i
    end

    test "includes real-world impacts" do
      metadata = InsecureSession.vulnerability_metadata()

      assert is_list(metadata.real_world_impact)
      assert length(metadata.real_world_impact) >= 3

      # Should include business impacts
      impacts_text = Enum.join(metadata.real_world_impact, " ")
      assert impacts_text =~ ~r/account.*takeover/i
      assert impacts_text =~ ~r/unauthorized.*access/i
    end

    test "includes safe alternatives" do
      metadata = InsecureSession.vulnerability_metadata()

      assert is_list(metadata.safe_alternatives)
      assert length(metadata.safe_alternatives) >= 3

      # Should include specific Django settings
      safe_text = Enum.join(metadata.safe_alternatives, " ")
      assert safe_text =~ ~r/SESSION_COOKIE_SECURE.*=.*True/
      assert safe_text =~ ~r/SESSION_COOKIE_HTTPONLY.*=.*True/
      assert safe_text =~ ~r/CSRF_COOKIE_SECURE.*=.*True/
    end
  end

  describe "ast_enhancement/0" do
    test "returns AST enhancement rules" do
      ast = InsecureSession.ast_enhancement()

      assert is_map(ast)
      assert Map.has_key?(ast, :min_confidence)
      assert Map.has_key?(ast, :context_rules)
      assert Map.has_key?(ast, :confidence_rules)
      assert Map.has_key?(ast, :ast_rules)
    end

    test "includes context rules for session cookies" do
      ast = InsecureSession.ast_enhancement()
      context = ast.context_rules

      assert Map.has_key?(context, :cookie_settings)
      assert "SESSION_COOKIE_SECURE" in context.cookie_settings
      assert "SESSION_COOKIE_HTTPONLY" in context.cookie_settings
      assert "CSRF_COOKIE_SECURE" in context.cookie_settings

      assert Map.has_key?(context, :django_settings_files)
      assert "settings.py" in context.django_settings_files
      assert "settings/production.py" in context.django_settings_files
    end

    test "includes confidence adjustments" do
      ast = InsecureSession.ast_enhancement()
      adjustments = ast.confidence_rules.adjustments

      # High confidence for explicit False values
      assert adjustments.explicit_false_value > 0.8

      # Lower confidence if in development settings
      assert adjustments.in_development_settings < 0

      # Higher confidence in production settings
      assert adjustments.in_production_settings > 0
    end

    test "includes AST rules for settings analysis" do
      ast = InsecureSession.ast_enhancement()
      rules = ast.ast_rules

      assert Map.has_key?(rules, :settings_analysis)
      assert rules.settings_analysis.detect_cookie_configs == true
      assert rules.settings_analysis.check_environment_specific == true
    end
  end

  describe "detection capabilities" do
    test "detects SESSION_COOKIE_SECURE = False" do
      pattern = InsecureSession.pattern()

      code = """
      # Django settings.py
      DEBUG = False
      SESSION_COOKIE_SECURE = False  # Vulnerable!
      """

      assert Enum.any?(pattern.regex, &Regex.match?(&1, code))
    end

    test "detects SESSION_COOKIE_HTTPONLY = False" do
      pattern = InsecureSession.pattern()

      code = """
      # Production settings
      SESSION_COOKIE_HTTPONLY = False  # XSS vulnerability
      """

      assert Enum.any?(pattern.regex, &Regex.match?(&1, code))
    end

    test "detects CSRF_COOKIE_SECURE = False" do
      pattern = InsecureSession.pattern()

      code = """
      CSRF_USE_SESSIONS = True
      CSRF_COOKIE_SECURE = False  # Insecure
      """

      assert Enum.any?(pattern.regex, &Regex.match?(&1, code))
    end

    test "detects SESSION_COOKIE_SAMESITE = None" do
      pattern = InsecureSession.pattern()

      code = """
      SESSION_COOKIE_SAMESITE = None  # CSRF risk
      """

      assert Enum.any?(pattern.regex, &Regex.match?(&1, code))
    end

    test "does not match secure configurations" do
      pattern = InsecureSession.pattern()

      safe_code = """
      # Secure settings
      SESSION_COOKIE_SECURE = True
      SESSION_COOKIE_HTTPONLY = True
      SESSION_COOKIE_SAMESITE = 'Strict'
      CSRF_COOKIE_SECURE = True
      """

      refute Enum.any?(pattern.regex, &Regex.match?(&1, safe_code))
    end

    test "does not match when setting is commented out" do
      pattern = InsecureSession.pattern()

      code = """
      # SESSION_COOKIE_SECURE = False
      # Disabled for now
      """

      refute Enum.any?(pattern.regex, &Regex.match?(&1, code))
    end
  end

  describe "enhanced_pattern/0" do
    test "uses ast_enhancement" do
      enhanced = InsecureSession.enhanced_pattern()

      assert enhanced.id == "django-insecure-session"
      assert enhanced.ast_enhancement == InsecureSession.ast_enhancement()
    end
  end
end
