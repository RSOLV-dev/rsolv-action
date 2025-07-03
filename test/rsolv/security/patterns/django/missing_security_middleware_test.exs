defmodule Rsolv.Security.Patterns.Django.MissingSecurityMiddlewareTest do
  use ExUnit.Case
  
  alias Rsolv.Security.Patterns.Django.MissingSecurityMiddleware
  alias Rsolv.Security.Pattern
  
  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = MissingSecurityMiddleware.pattern()
      
      assert pattern.id == "django-missing-security-middleware"
      assert pattern.name == "Django Missing Security Middleware"
      assert pattern.description == "Missing important security middleware in Django settings"
      assert pattern.type == :misconfiguration
      assert pattern.severity == :high
      assert pattern.languages == ["python"]
      assert pattern.frameworks == ["django"]
      assert pattern.cwe_id == "CWE-16"
      assert pattern.owasp_category == "A05:2021"
      assert pattern.recommendation =~ "Add security middleware"
    end
    
    test "includes patterns for missing SecurityMiddleware" do
      pattern = MissingSecurityMiddleware.pattern()
      
      # Should detect missing django.middleware.security.SecurityMiddleware
      assert Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, "MIDDLEWARE = ['django.middleware.common.CommonMiddleware']")
      end)
    end
    
    test "includes patterns for missing CsrfViewMiddleware" do
      pattern = MissingSecurityMiddleware.pattern()
      
      # Should detect missing django.middleware.csrf.CsrfViewMiddleware
      assert Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, "MIDDLEWARE = ['django.middleware.security.SecurityMiddleware']")
      end)
    end
    
    test "includes patterns for missing XFrameOptionsMiddleware" do
      pattern = MissingSecurityMiddleware.pattern()
      
      # Should detect missing django.middleware.clickjacking.XFrameOptionsMiddleware
      assert Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, "MIDDLEWARE = ['django.middleware.security.SecurityMiddleware', 'django.middleware.csrf.CsrfViewMiddleware']")
      end)
    end
    
    test "includes test cases for vulnerable code" do
      pattern = MissingSecurityMiddleware.pattern()
      
      assert is_list(pattern.test_cases.vulnerable)
      assert length(pattern.test_cases.vulnerable) >= 3
      
      # Check for middleware list without security middleware
      assert Enum.any?(pattern.test_cases.vulnerable, &(&1 =~ "CommonMiddleware"))
    end
    
    test "includes test cases for safe code" do
      pattern = MissingSecurityMiddleware.pattern()
      
      assert is_list(pattern.test_cases.safe)
      assert length(pattern.test_cases.safe) >= 1
      
      # Check for complete middleware configuration
      assert Enum.any?(pattern.test_cases.safe, &(&1 =~ "SecurityMiddleware"))
      assert Enum.any?(pattern.test_cases.safe, &(&1 =~ "CsrfViewMiddleware"))
      assert Enum.any?(pattern.test_cases.safe, &(&1 =~ "XFrameOptionsMiddleware"))
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "includes comprehensive vulnerability details" do
      metadata = MissingSecurityMiddleware.vulnerability_metadata()
      
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
      metadata = MissingSecurityMiddleware.vulnerability_metadata()
      cve_examples = metadata.cve_examples
      
      assert is_list(cve_examples)
      assert length(cve_examples) >= 3
      
      # Check for CVEs related to missing security headers/middleware
      cve_ids = Enum.map(cve_examples, & &1.id)
      assert Enum.any?(cve_ids, &(&1 =~ ~r/CVE-\d{4}-\d+/))
    end
    
    test "includes attack vectors" do
      metadata = MissingSecurityMiddleware.vulnerability_metadata()
      
      assert is_list(metadata.attack_vectors)
      assert length(metadata.attack_vectors) >= 5
      
      # Should include various attacks prevented by security middleware
      vectors_text = Enum.join(metadata.attack_vectors, " ")
      assert vectors_text =~ ~r/clickjacking/i
      assert vectors_text =~ ~r/csrf/i
      assert vectors_text =~ ~r/xss/i
      assert vectors_text =~ ~r/ssl.*strip/i
    end
    
    test "includes real-world impacts" do
      metadata = MissingSecurityMiddleware.vulnerability_metadata()
      
      assert is_list(metadata.real_world_impact)
      assert length(metadata.real_world_impact) >= 4
      
      # Should include business impacts
      impacts_text = Enum.join(metadata.real_world_impact, " ")
      assert impacts_text =~ ~r/compliance/i
      assert impacts_text =~ ~r/reputation/i
    end
    
    test "includes safe alternatives" do
      metadata = MissingSecurityMiddleware.vulnerability_metadata()
      
      assert is_list(metadata.safe_alternatives)
      assert length(metadata.safe_alternatives) >= 3
      
      # Should include complete middleware configuration examples
      safe_text = Enum.join(metadata.safe_alternatives, " ")
      assert safe_text =~ ~r/MIDDLEWARE.*SecurityMiddleware/s
      assert safe_text =~ ~r/MIDDLEWARE.*CsrfViewMiddleware/s
      assert safe_text =~ ~r/MIDDLEWARE.*XFrameOptionsMiddleware/s
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns AST enhancement rules" do
      ast = MissingSecurityMiddleware.ast_enhancement()
      
      assert is_map(ast)
      assert Map.has_key?(ast, :min_confidence)
      assert Map.has_key?(ast, :context_rules)
      assert Map.has_key?(ast, :confidence_rules)
      assert Map.has_key?(ast, :ast_rules)
    end
    
    test "includes context rules for middleware detection" do
      ast = MissingSecurityMiddleware.ast_enhancement()
      context = ast.context_rules
      
      assert Map.has_key?(context, :security_middleware)
      assert "django.middleware.security.SecurityMiddleware" in context.security_middleware
      assert "django.middleware.csrf.CsrfViewMiddleware" in context.security_middleware
      assert "django.middleware.clickjacking.XFrameOptionsMiddleware" in context.security_middleware
      
      assert Map.has_key?(context, :django_settings_files)
      assert "settings.py" in context.django_settings_files
    end
    
    test "includes confidence adjustments" do
      ast = MissingSecurityMiddleware.ast_enhancement()
      adjustments = ast.confidence_rules.adjustments
      
      # High confidence when multiple security middleware missing
      assert adjustments.all_security_missing > 0.9
      
      # Medium confidence for individual missing middleware
      assert adjustments.single_middleware_missing > 0.5
      
      # Lower confidence in development settings
      assert adjustments.in_development_settings < 0
    end
    
    test "includes AST rules for middleware analysis" do
      ast = MissingSecurityMiddleware.ast_enhancement()
      rules = ast.ast_rules
      
      assert Map.has_key?(rules, :middleware_analysis)
      assert rules.middleware_analysis.detect_middleware_list == true
      assert rules.middleware_analysis.check_ordering == true
      assert rules.middleware_analysis.validate_completeness == true
    end
  end
  
  describe "detection capabilities" do
    test "detects missing SecurityMiddleware" do
      pattern = MissingSecurityMiddleware.pattern()
      
      vulnerable_code = """
      MIDDLEWARE = [
          'django.middleware.common.CommonMiddleware',
          'django.middleware.csrf.CsrfViewMiddleware',
      ]
      """
      
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end
    
    test "detects missing CsrfViewMiddleware" do
      pattern = MissingSecurityMiddleware.pattern()
      
      vulnerable_code = """
      MIDDLEWARE = [
          'django.middleware.security.SecurityMiddleware',
          'django.middleware.common.CommonMiddleware',
      ]
      """
      
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end
    
    test "detects missing XFrameOptionsMiddleware" do
      pattern = MissingSecurityMiddleware.pattern()
      
      vulnerable_code = """
      MIDDLEWARE = [
          'django.middleware.security.SecurityMiddleware',
          'django.middleware.csrf.CsrfViewMiddleware',
          'django.middleware.common.CommonMiddleware',
      ]
      """
      
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end
    
    test "does not match when all security middleware present" do
      pattern = MissingSecurityMiddleware.pattern()
      
      safe_code = """
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
      
      refute Enum.any?(pattern.regex, &Regex.match?(&1, safe_code))
    end
    
    test "handles MIDDLEWARE_CLASSES (old Django)" do
      pattern = MissingSecurityMiddleware.pattern()
      
      vulnerable_code = """
      MIDDLEWARE_CLASSES = [
          'django.middleware.common.CommonMiddleware',
      ]
      """
      
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end
  end
  
  describe "enhanced_pattern/0" do
    test "uses ast_enhancement" do
      enhanced = MissingSecurityMiddleware.enhanced_pattern()
      
      assert enhanced.id == "django-missing-security-middleware"
      assert enhanced.ast_enhancement == MissingSecurityMiddleware.ast_enhancement()
    end
  end
end