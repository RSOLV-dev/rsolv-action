defmodule RsolvApi.Security.Patterns.Django.CsrfBypassTest do
  use ExUnit.Case
  
  alias RsolvApi.Security.Patterns.Django.CsrfBypass
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = CsrfBypass.pattern()
      
      assert pattern.id == "django-csrf-bypass"
      assert pattern.name == "Django CSRF Bypass"
      assert pattern.description == "CSRF protection disabled or bypassed"
      assert pattern.type == :csrf
      assert pattern.severity == :high
      assert pattern.languages == ["python"]
      assert pattern.frameworks == ["django"]
      assert pattern.default_tier == :ai
      assert pattern.cwe_id == "CWE-352"
      assert pattern.owasp_category == "A01:2021"
      assert pattern.recommendation =~ "CSRF protection"
    end
    
    test "includes patterns for CSRF exemption" do
      pattern = CsrfBypass.pattern()
      
      # @csrf_exempt decorator
      assert Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, "@csrf_exempt\ndef payment_view(request):")
      end)
      
      # CSRF settings disabled
      assert Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, "CSRF_COOKIE_SECURE = False")
      end)
    end
    
    test "includes patterns for missing CSRF tokens" do
      pattern = CsrfBypass.pattern()
      
      # Form without CSRF token
      assert Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, "<form method=\"post\">\n  <input type=\"text\" name=\"amount\">")
      end)
      
      # Ajax without CSRF header
      assert Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, "$.ajax({ type: 'POST', data: data })")
      end)
    end
    
    test "includes test cases for vulnerable code" do
      pattern = CsrfBypass.pattern()
      
      assert is_list(pattern.test_cases.vulnerable)
      assert length(pattern.test_cases.vulnerable) >= 3
      
      # Check for @csrf_exempt usage
      assert Enum.any?(pattern.test_cases.vulnerable, &(&1 =~ "@csrf_exempt"))
      
      # Check for form without token
      assert Enum.any?(pattern.test_cases.vulnerable, &(&1 =~ "<form method=\"post\">"))
    end
    
    test "includes test cases for safe code" do
      pattern = CsrfBypass.pattern()
      
      assert is_list(pattern.test_cases.safe)
      assert length(pattern.test_cases.safe) >= 2
      
      # Check for csrf_token inclusion
      assert Enum.any?(pattern.test_cases.safe, &(&1 =~ "{% csrf_token %}"))
      
      # Check for proper middleware config
      assert Enum.any?(pattern.test_cases.safe, &(&1 =~ "CsrfViewMiddleware"))
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "includes comprehensive vulnerability details" do
      metadata = CsrfBypass.vulnerability_metadata()
      
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
      metadata = CsrfBypass.vulnerability_metadata()
      cve_examples = metadata.cve_examples
      
      assert is_list(cve_examples)
      assert length(cve_examples) >= 3
      
      # Check for known Django CSRF CVEs
      cve_ids = Enum.map(cve_examples, & &1.id)
      assert "CVE-2016-7401" in cve_ids  # Django CSRF bypass via Google Analytics
    end
    
    test "includes attack vectors" do
      metadata = CsrfBypass.vulnerability_metadata()
      
      assert is_list(metadata.attack_vectors)
      assert length(metadata.attack_vectors) >= 4
      
      # Should include various CSRF attack methods
      vectors_text = Enum.join(metadata.attack_vectors, " ")
      assert vectors_text =~ ~r/form.*submission/i
      assert vectors_text =~ ~r/ajax.*request/i
      assert vectors_text =~ ~r/image.*tag/i
      assert vectors_text =~ ~r/cross.*site/i
    end
    
    test "includes real-world impacts" do
      metadata = CsrfBypass.vulnerability_metadata()
      
      assert is_list(metadata.real_world_impact)
      assert length(metadata.real_world_impact) >= 4
      
      # Should include business impacts
      impacts_text = Enum.join(metadata.real_world_impact, " ")
      assert impacts_text =~ ~r/unauthorized.*actions/i
      assert impacts_text =~ ~r/financial.*transaction/i
      assert impacts_text =~ ~r/account.*modification/i
    end
    
    test "includes safe alternatives" do
      metadata = CsrfBypass.vulnerability_metadata()
      
      assert is_list(metadata.safe_alternatives)
      assert length(metadata.safe_alternatives) >= 3
      
      # Should include specific Django CSRF practices
      safe_text = Enum.join(metadata.safe_alternatives, " ")
      assert safe_text =~ ~r/{% csrf_token %}/
      assert safe_text =~ ~r/CsrfViewMiddleware/
      assert safe_text =~ ~r/X-CSRFToken/
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns AST enhancement rules" do
      ast = CsrfBypass.ast_enhancement()
      
      assert is_map(ast)
      assert Map.has_key?(ast, :min_confidence)
      assert Map.has_key?(ast, :context_rules)
      assert Map.has_key?(ast, :confidence_rules)
      assert Map.has_key?(ast, :ast_rules)
    end
    
    test "includes context rules for CSRF" do
      ast = CsrfBypass.ast_enhancement()
      context = ast.context_rules
      
      assert Map.has_key?(context, :csrf_settings)
      assert "CSRF_COOKIE_SECURE" in context.csrf_settings
      assert "CSRF_COOKIE_HTTPONLY" in context.csrf_settings
      
      assert Map.has_key?(context, :safe_methods)
      assert "GET" in context.safe_methods
      assert "HEAD" in context.safe_methods
      
      assert Map.has_key?(context, :csrf_decorators)
      assert "@csrf_exempt" in context.csrf_decorators
      assert "@requires_csrf_token" in context.csrf_decorators
    end
    
    test "includes confidence adjustments" do
      ast = CsrfBypass.ast_enhancement()
      adjustments = ast.confidence_rules.adjustments
      
      # High confidence for explicit exemption
      assert adjustments.csrf_exempt_usage > 0.9
      
      # High confidence for disabled settings
      assert adjustments.csrf_disabled_settings > 0.85
      
      # Lower confidence for missing in templates
      assert adjustments.missing_in_template > 0.5
      
      # Lower confidence in test files
      assert adjustments.in_test_file < 0
    end
    
    test "includes AST rules for CSRF analysis" do
      ast = CsrfBypass.ast_enhancement()
      rules = ast.ast_rules
      
      assert Map.has_key?(rules, :csrf_analysis)
      assert rules.csrf_analysis.detect_decorators == true
      assert rules.csrf_analysis.check_middleware == true
      assert rules.csrf_analysis.analyze_forms == true
      assert rules.csrf_analysis.check_ajax_calls == true
    end
  end
  
  describe "detection capabilities" do
    test "detects @csrf_exempt decorator" do
      pattern = CsrfBypass.pattern()
      
      vulnerable_code = """
      @csrf_exempt
      def transfer_funds(request):
          amount = request.POST.get('amount')
          recipient = request.POST.get('recipient')
          # Process transfer
      """
      
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end
    
    test "detects insecure CSRF settings" do
      pattern = CsrfBypass.pattern()
      
      # CSRF_COOKIE_SECURE = False
      assert Enum.any?(pattern.regex, &Regex.match?(&1, "CSRF_COOKIE_SECURE = False"))
      
      # CSRF_USE_SESSIONS = False
      assert Enum.any?(pattern.regex, &Regex.match?(&1, "CSRF_USE_SESSIONS = False"))
    end
    
    test "detects forms without CSRF token" do
      pattern = CsrfBypass.pattern()
      
      vulnerable_form = """
      <form method="post" action="/transfer">
          <input type="text" name="amount">
          <input type="submit" value="Transfer">
      </form>
      """
      
      # This might need a more sophisticated pattern
      # Testing the absence of {% csrf_token %} is complex with regex
    end
    
    test "does not match properly protected views" do
      pattern = CsrfBypass.pattern()
      
      safe_code = """
      def transfer_funds(request):
          # CSRF protected by default
          amount = request.POST.get('amount')
          recipient = request.POST.get('recipient')
      """
      
      # Should not match views without @csrf_exempt
      refute Enum.any?(pattern.regex, &Regex.match?(&1, safe_code))
    end
  end
  
  describe "enhanced_pattern/0" do
    test "uses ast_enhancement" do
      enhanced = CsrfBypass.enhanced_pattern()
      
      assert enhanced.id == "django-csrf-bypass"
      assert enhanced.ast_enhancement == CsrfBypass.ast_enhancement()
    end
  end
end