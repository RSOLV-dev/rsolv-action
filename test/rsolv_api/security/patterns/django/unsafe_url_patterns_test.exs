defmodule RsolvApi.Security.Patterns.Django.UnsafeUrlPatternsTest do
  use ExUnit.Case
  
  alias RsolvApi.Security.Patterns.Django.UnsafeUrlPatterns
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = UnsafeUrlPatterns.pattern()
      
      assert pattern.id == "django-unsafe-url-patterns"
      assert pattern.name == "Django Unsafe URL Patterns"
      assert pattern.description == "URL patterns that may expose sensitive endpoints"
      assert pattern.type == :misconfiguration
      assert pattern.severity == :medium
      assert pattern.languages == ["python"]
      assert pattern.frameworks == ["django"]
      assert pattern.default_tier == :public
      assert pattern.cwe_id == "CWE-284"
      assert pattern.owasp_category == "A01:2021"
      assert pattern.recommendation =~ "Use specific URL patterns"
    end
    
    test "includes patterns for dangerous admin URL exposure" do
      pattern = UnsafeUrlPatterns.pattern()
      
      # Default admin URL exposure
      assert Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, "path('admin/', admin.site.urls)")
      end)
      
      # Admin without trailing slash (even more dangerous)
      assert Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, "path('admin', admin.site.urls)")
      end)
    end
    
    test "includes patterns for wildcard patterns" do
      pattern = UnsafeUrlPatterns.pattern()
      
      # Dangerous wildcard patterns
      assert Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, "path('.*', catch_all_view)")
      end)
      
      # re_path with wildcard
      assert Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, "re_path(r'^.*', some_view)")
      end)
    end
    
    test "includes patterns for debug toolbar exposure" do
      pattern = UnsafeUrlPatterns.pattern()
      
      # Debug toolbar included without DEBUG check
      assert Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, "include('debug_toolbar.urls')")
      end)
      
      # Django silk profiler exposure
      assert Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, "include('silk.urls')")
      end)
    end
    
    test "includes test cases for vulnerable code" do
      pattern = UnsafeUrlPatterns.pattern()
      
      assert is_list(pattern.test_cases.vulnerable)
      assert length(pattern.test_cases.vulnerable) >= 3
      
      # Check for admin exposure
      assert Enum.any?(pattern.test_cases.vulnerable, &(&1 =~ "path('admin'"))
      
      # Check for wildcard pattern
      assert Enum.any?(pattern.test_cases.vulnerable, &(&1 =~ ".*"))
      
      # Check for debug toolbar
      assert Enum.any?(pattern.test_cases.vulnerable, &(&1 =~ "debug_toolbar"))
    end
    
    test "includes test cases for safe code" do
      pattern = UnsafeUrlPatterns.pattern()
      
      assert is_list(pattern.test_cases.safe)
      assert length(pattern.test_cases.safe) >= 2
      
      # Check for secure admin URL
      assert Enum.any?(pattern.test_cases.safe, &(&1 =~ "secure-admin-url"))
      
      # Check for conditional debug inclusion
      assert Enum.any?(pattern.test_cases.safe, &(&1 =~ "if settings.DEBUG"))
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "includes comprehensive vulnerability details" do
      metadata = UnsafeUrlPatterns.vulnerability_metadata()
      
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
      metadata = UnsafeUrlPatterns.vulnerability_metadata()
      references = metadata.references
      
      assert is_list(references)
      assert length(references) >= 3
      
      # Check for CWE reference
      assert Enum.any?(references, &(&1.type == :cwe && &1.id == "CWE-284"))
      
      # Check for OWASP reference
      assert Enum.any?(references, &(&1.type == :owasp))
      
      # Check for Django-specific reference
      assert Enum.any?(references, &(&1.type == :django))
    end
    
    test "includes attack vectors" do
      metadata = UnsafeUrlPatterns.vulnerability_metadata()
      
      assert is_list(metadata.attack_vectors)
      assert length(metadata.attack_vectors) >= 4
      
      # Should include various attack scenarios
      vectors_text = Enum.join(metadata.attack_vectors, " ")
      assert vectors_text =~ ~r/admin.*brute.*force/i
      assert vectors_text =~ ~r/information.*disclosure/i
      assert vectors_text =~ ~r/debug.*toolbar/i
    end
    
    test "includes real-world impacts" do
      metadata = UnsafeUrlPatterns.vulnerability_metadata()
      
      assert is_list(metadata.real_world_impact)
      assert length(metadata.real_world_impact) >= 4
      
      # Should include business impacts
      impacts_text = Enum.join(metadata.real_world_impact, " ")
      assert impacts_text =~ ~r/admin.*panel.*compromise/i
      assert impacts_text =~ ~r/sensitive.*information/i
      assert impacts_text =~ ~r/data.*breach/i
    end
    
    test "includes CVE examples" do
      metadata = UnsafeUrlPatterns.vulnerability_metadata()
      
      assert is_list(metadata.cve_examples)
      assert length(metadata.cve_examples) >= 2
      
      # Should include debug toolbar vulnerability
      cve_text = Enum.join(Enum.map(metadata.cve_examples, &(&1.description)), " ")
      assert cve_text =~ ~r/debug.*toolbar/i
    end
    
    test "includes safe alternatives" do
      metadata = UnsafeUrlPatterns.vulnerability_metadata()
      
      assert is_list(metadata.safe_alternatives)
      assert length(metadata.safe_alternatives) >= 3
      
      # Should include specific Django URL safety practices
      safe_text = Enum.join(metadata.safe_alternatives, " ")
      assert safe_text =~ ~r/specific.*URL.*patterns/i
      assert safe_text =~ ~r/admin.*URL/i
      assert safe_text =~ ~r/DEBUG.*check/i
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns AST enhancement rules" do
      ast = UnsafeUrlPatterns.ast_enhancement()
      
      assert is_map(ast)
      assert Map.has_key?(ast, :min_confidence)
      assert Map.has_key?(ast, :context_rules)
      assert Map.has_key?(ast, :confidence_rules)
      assert Map.has_key?(ast, :ast_rules)
    end
    
    test "includes context rules for URL patterns" do
      ast = UnsafeUrlPatterns.ast_enhancement()
      context = ast.context_rules
      
      assert Map.has_key?(context, :url_functions)
      assert "path" in context.url_functions
      assert "re_path" in context.url_functions
      assert "include" in context.url_functions
      
      assert Map.has_key?(context, :dangerous_patterns)
      assert "admin" in context.dangerous_patterns
      assert "debug_toolbar" in context.dangerous_patterns
      
      assert Map.has_key?(context, :safe_patterns)
      assert "if settings.DEBUG" in context.safe_patterns
    end
    
    test "includes confidence adjustments" do
      ast = UnsafeUrlPatterns.ast_enhancement()
      adjustments = ast.confidence_rules.adjustments
      
      # High confidence for dangerous patterns
      assert adjustments.default_admin_url > 0.8
      assert adjustments.wildcard_patterns > 0.7
      
      # Lower confidence in development
      assert adjustments.in_development_settings < 0
      assert adjustments.conditional_inclusion < 0
    end
    
    test "includes AST rules for URL analysis" do
      ast = UnsafeUrlPatterns.ast_enhancement()
      rules = ast.ast_rules
      
      assert Map.has_key?(rules, :url_analysis)
      assert rules.url_analysis.detect_admin_patterns == true
      assert rules.url_analysis.check_wildcard_usage == true
      assert rules.url_analysis.analyze_debug_includes == true
    end
  end
  
  describe "detection capabilities" do
    test "detects default admin URL exposure" do
      pattern = UnsafeUrlPatterns.pattern()
      
      vulnerable_code = """
      urlpatterns = [
          path('admin/', admin.site.urls),
          path('', views.home, name='home'),
      ]
      """
      
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end
    
    test "detects wildcard URL patterns" do
      pattern = UnsafeUrlPatterns.pattern()
      
      vulnerable_code = """
      urlpatterns = [
          path('api/', include('api.urls')),
          path('.*', views.catch_all),
      ]
      """
      
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end
    
    test "detects debug toolbar exposure" do
      pattern = UnsafeUrlPatterns.pattern()
      
      vulnerable_code = """
      urlpatterns = [
          path('', include('myapp.urls')),
          path('__debug__/', include('debug_toolbar.urls')),
      ]
      """
      
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end
    
    test "does not match secure URL patterns" do
      pattern = UnsafeUrlPatterns.pattern()
      
      safe_code = """
      urlpatterns = [
          path('secure-admin-interface/', admin.site.urls),
          path('api/v1/', include('api.urls')),
      ]
      
      if settings.DEBUG:
          urlpatterns += [path('__debug__/', include('debug_toolbar.urls'))]
      """
      
      # Should not match secure admin URL or conditional debug inclusion
      refute Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, "secure-admin-interface")
      end)
    end
  end
  
  describe "enhanced_pattern/0" do
    test "uses ast_enhancement" do
      enhanced = UnsafeUrlPatterns.enhanced_pattern()
      
      assert enhanced.id == "django-unsafe-url-patterns"
      assert enhanced.ast_enhancement == UnsafeUrlPatterns.ast_enhancement()
    end
  end
end