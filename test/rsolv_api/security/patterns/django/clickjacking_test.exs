defmodule RsolvApi.Security.Patterns.Django.ClickjackingTest do
  use ExUnit.Case
  
  alias RsolvApi.Security.Patterns.Django.Clickjacking
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = Clickjacking.pattern()
      
      assert pattern.id == "django-clickjacking"
      assert pattern.name == "Django Clickjacking Vulnerability"
      assert pattern.description == "Missing X-Frame-Options header protection"
      assert pattern.type == :clickjacking
      assert pattern.severity == :medium
      assert pattern.languages == ["python"]
      assert pattern.frameworks == ["django"]
      assert pattern.cwe_id == "CWE-1021"
      assert pattern.owasp_category == "A05:2021"
      assert pattern.recommendation =~ "X_FRAME_OPTIONS"
    end
    
    test "includes patterns for X-Frame-Options misconfiguration" do
      pattern = Clickjacking.pattern()
      
      # ALLOWALL setting
      assert Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, "X_FRAME_OPTIONS = 'ALLOWALL'")
      end)
      
      # xframe_options_exempt decorator
      assert Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, "@xframe_options_exempt\ndef my_view(request):")
      end)
      
      # xframe_options_sameorigin decorator
      assert Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, "@xframe_options_sameorigin\ndef my_view(request):")
      end)
    end
    
    test "includes test cases for vulnerable code" do
      pattern = Clickjacking.pattern()
      
      assert is_list(pattern.test_cases.vulnerable)
      assert length(pattern.test_cases.vulnerable) >= 2
      
      # Check for ALLOWALL setting
      assert Enum.any?(pattern.test_cases.vulnerable, &(&1 =~ "X_FRAME_OPTIONS = 'ALLOWALL'"))
      
      # Check for decorator usage
      assert Enum.any?(pattern.test_cases.vulnerable, &(&1 =~ "@xframe_options_exempt"))
    end
    
    test "includes test cases for safe code" do
      pattern = Clickjacking.pattern()
      
      assert is_list(pattern.test_cases.safe)
      assert length(pattern.test_cases.safe) >= 2
      
      # Check for DENY setting
      assert Enum.any?(pattern.test_cases.safe, &(&1 =~ "X_FRAME_OPTIONS = 'DENY'"))
      
      # Check for SAMEORIGIN setting
      assert Enum.any?(pattern.test_cases.safe, &(&1 =~ "X_FRAME_OPTIONS = 'SAMEORIGIN'"))
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "includes comprehensive vulnerability details" do
      metadata = Clickjacking.vulnerability_metadata()
      
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
    
    test "includes relevant references" do
      metadata = Clickjacking.vulnerability_metadata()
      references = metadata.references
      
      assert is_list(references)
      assert length(references) >= 3
      
      # Check for CWE reference
      assert Enum.any?(references, &(&1.type == :cwe && &1.id == "CWE-1021"))
      
      # Check for OWASP reference
      assert Enum.any?(references, &(&1.type == :owasp))
    end
    
    test "includes attack vectors" do
      metadata = Clickjacking.vulnerability_metadata()
      
      assert is_list(metadata.attack_vectors)
      assert length(metadata.attack_vectors) >= 4
      
      # Should include various clickjacking techniques
      vectors_text = Enum.join(metadata.attack_vectors, " ")
      assert vectors_text =~ ~r/iframe/i
      assert vectors_text =~ ~r/frame/i
      assert vectors_text =~ ~r/transparent/i
      assert vectors_text =~ ~r/overlay/i
    end
    
    test "includes real-world impacts" do
      metadata = Clickjacking.vulnerability_metadata()
      
      assert is_list(metadata.real_world_impact)
      assert length(metadata.real_world_impact) >= 4
      
      # Should include business impacts
      impacts_text = Enum.join(metadata.real_world_impact, " ")
      assert impacts_text =~ ~r/click/i
      assert impacts_text =~ ~r/action/i
      assert impacts_text =~ ~r/unintended/i
    end
    
    test "includes safe alternatives" do
      metadata = Clickjacking.vulnerability_metadata()
      
      assert is_list(metadata.safe_alternatives)
      assert length(metadata.safe_alternatives) >= 3
      
      # Should include specific Django clickjacking defenses
      safe_text = Enum.join(metadata.safe_alternatives, " ")
      assert safe_text =~ ~r/X_FRAME_OPTIONS/
      assert safe_text =~ ~r/XFrameOptionsMiddleware/
      assert safe_text =~ ~r/Content-Security-Policy/
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns AST enhancement rules" do
      ast = Clickjacking.ast_enhancement()
      
      assert is_map(ast)
      assert Map.has_key?(ast, :min_confidence)
      assert Map.has_key?(ast, :context_rules)
      assert Map.has_key?(ast, :confidence_rules)
      assert Map.has_key?(ast, :ast_rules)
    end
    
    test "includes context rules for clickjacking" do
      ast = Clickjacking.ast_enhancement()
      context = ast.context_rules
      
      assert Map.has_key?(context, :settings_names)
      assert "X_FRAME_OPTIONS" in context.settings_names
      
      assert Map.has_key?(context, :decorators)
      assert "@xframe_options_exempt" in context.decorators
      assert "@xframe_options_deny" in context.decorators
      assert "@xframe_options_sameorigin" in context.decorators
      
      assert Map.has_key?(context, :middleware_names)
      assert "XFrameOptionsMiddleware" in context.middleware_names
    end
    
    test "includes confidence adjustments" do
      ast = Clickjacking.ast_enhancement()
      adjustments = ast.confidence_rules.adjustments
      
      # High confidence for ALLOWALL
      assert adjustments.allowall_setting > 0.9
      
      # High confidence for exempt decorator
      assert adjustments.exempt_decorator > 0.85
      
      # Lower confidence in test files
      assert adjustments.in_test_file < 0
      
      # Lower confidence with CSP header
      assert adjustments.has_csp_header < 0
    end
    
    test "includes AST rules for clickjacking analysis" do
      ast = Clickjacking.ast_enhancement()
      rules = ast.ast_rules
      
      assert Map.has_key?(rules, :clickjacking_analysis)
      assert rules.clickjacking_analysis.check_settings == true
      assert rules.clickjacking_analysis.detect_decorators == true
      assert rules.clickjacking_analysis.check_middleware == true
      assert rules.clickjacking_analysis.analyze_csp == true
    end
  end
  
  describe "detection capabilities" do
    test "detects ALLOWALL setting" do
      pattern = Clickjacking.pattern()
      
      vulnerable_code = """
      # settings.py
      X_FRAME_OPTIONS = 'ALLOWALL'
      """
      
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end
    
    test "detects xframe_options_exempt decorator" do
      pattern = Clickjacking.pattern()
      
      vulnerable_code = """
      @xframe_options_exempt
      def payment_iframe(request):
          # This view can be embedded anywhere
          return render(request, 'payment.html')
      """
      
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end
    
    test "detects xframe_options_sameorigin decorator" do
      pattern = Clickjacking.pattern()
      
      # This is actually less secure than DENY
      vulnerable_code = """
      @xframe_options_sameorigin
      def sensitive_action(request):
          # Still vulnerable to same-origin clickjacking
          return render(request, 'sensitive.html')
      """
      
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end
    
    test "does not match properly protected views" do
      pattern = Clickjacking.pattern()
      
      safe_code = """
      # settings.py
      X_FRAME_OPTIONS = 'DENY'
      
      # view.py
      def secure_view(request):
          # Protected by default
          return render(request, 'secure.html')
      """
      
      # Should not match safe configurations
      refute Enum.any?(pattern.regex, &Regex.match?(&1, "X_FRAME_OPTIONS = 'DENY'"))
    end
  end
  
  describe "enhanced_pattern/0" do
    test "uses ast_enhancement" do
      enhanced = Clickjacking.enhanced_pattern()
      
      assert enhanced.id == "django-clickjacking"
      assert enhanced.ast_enhancement == Clickjacking.ast_enhancement()
    end
  end
end