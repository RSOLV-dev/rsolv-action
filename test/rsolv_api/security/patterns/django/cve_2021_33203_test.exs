defmodule RsolvApi.Security.Patterns.Django.Cve202133203Test do
  use ExUnit.Case
  
  alias RsolvApi.Security.Patterns.Django.Cve202133203
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = Cve202133203.pattern()
      
      assert pattern.id == "django-cve-2021-33203"
      assert pattern.name == "Django CVE-2021-33203 - Directory Traversal via admindocs"
      assert pattern.description == "Directory traversal via django.contrib.admindocs TemplateDetailView"
      assert pattern.type == :path_traversal
      assert pattern.severity == :medium
      assert pattern.languages == ["python"]
      assert pattern.frameworks == ["django"]
      assert pattern.default_tier == :enterprise
      assert pattern.cwe_id == "CWE-22"
      assert pattern.owasp_category == "A01:2021"
      assert pattern.recommendation =~ "Update Django"
    end
    
    test "includes patterns for vulnerable TemplateDetailView usage" do
      pattern = Cve202133203.pattern()
      
      # Vulnerable django.contrib.admindocs usage
      assert Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, "django.contrib.admindocs")
      end)
      
      # TemplateDetailView vulnerable patterns
      assert Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, "TemplateDetailView")
      end)
      
      # Path join vulnerabilities
      assert Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, "path")
      end)
    end
    
    test "includes patterns for admindocs URL configurations" do
      pattern = Cve202133203.pattern()
      
      # Admindocs URL patterns that could be exploited
      assert Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, "path('admin/doc/', include('django.contrib.admindocs.urls'))")
      end)
      
      # Template parameter in URL
      assert Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, "templates/")
      end)
    end
    
    test "includes test cases for vulnerable code" do
      pattern = Cve202133203.pattern()
      
      assert is_list(pattern.test_cases.vulnerable)
      assert length(pattern.test_cases.vulnerable) >= 3
      
      # Check for admindocs inclusion
      assert Enum.any?(pattern.test_cases.vulnerable, &(&1 =~ "admindocs"))
      
      # Check for TemplateDetailView
      assert Enum.any?(pattern.test_cases.vulnerable, &(&1 =~ "TemplateDetailView"))
      
      # Check for path traversal example
      assert Enum.any?(pattern.test_cases.vulnerable, &(&1 =~ "../"))
    end
    
    test "includes test cases for safe code" do
      pattern = Cve202133203.pattern()
      
      assert is_list(pattern.test_cases.safe)
      assert length(pattern.test_cases.safe) >= 2
      
      # Check for updated Django version
      assert Enum.any?(pattern.test_cases.safe, &(&1 =~ "Django"))
      
      # Check for path validation
      assert Enum.any?(pattern.test_cases.safe, &(&1 =~ "safe_join"))
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "includes comprehensive vulnerability details" do
      metadata = Cve202133203.vulnerability_metadata()
      
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
      metadata = Cve202133203.vulnerability_metadata()
      references = metadata.references
      
      assert is_list(references)
      assert length(references) >= 4
      
      # Check for CVE reference
      assert Enum.any?(references, &(&1.type == :cve && &1.id == "CVE-2021-33203"))
      
      # Check for CWE reference
      assert Enum.any?(references, &(&1.type == :cwe && &1.id == "CWE-22"))
      
      # Check for OWASP reference
      assert Enum.any?(references, &(&1.type == :owasp))
      
      # Check for Django-specific reference
      assert Enum.any?(references, &(&1.type == :django))
    end
    
    test "includes attack vectors" do
      metadata = Cve202133203.vulnerability_metadata()
      
      assert is_list(metadata.attack_vectors)
      assert length(metadata.attack_vectors) >= 5
      
      # Should include specific attack methods
      vectors_text = Enum.join(metadata.attack_vectors, " ")
      assert vectors_text =~ ~r/admindocs/i
      assert vectors_text =~ ~r/template.*path/i
      assert vectors_text =~ ~r/directory.*traversal/i
    end
    
    test "includes real-world impacts" do
      metadata = Cve202133203.vulnerability_metadata()
      
      assert is_list(metadata.real_world_impact)
      assert length(metadata.real_world_impact) >= 4
      
      # Should include business impacts
      impacts_text = Enum.join(metadata.real_world_impact, " ")
      assert impacts_text =~ ~r/file.*disclosure/i
      assert impacts_text =~ ~r/sensitive.*information/i
      assert impacts_text =~ ~r/configuration/i
    end
    
    test "includes CVE examples" do
      metadata = Cve202133203.vulnerability_metadata()
      
      assert is_list(metadata.cve_examples)
      assert length(metadata.cve_examples) >= 2
      
      # Should include main CVE
      cve_ids = Enum.map(metadata.cve_examples, &(&1.id))
      assert "CVE-2021-33203" in cve_ids
      
      # Should include related path traversal CVEs
      cve_text = Enum.join(Enum.map(metadata.cve_examples, &(&1.description)), " ")
      assert cve_text =~ ~r/traversal/i
    end
    
    test "includes safe alternatives" do
      metadata = Cve202133203.vulnerability_metadata()
      
      assert is_list(metadata.safe_alternatives)
      assert length(metadata.safe_alternatives) >= 3
      
      # Should include Django upgrade guidance
      safe_text = Enum.join(metadata.safe_alternatives, " ")
      assert safe_text =~ ~r/Django.*upgrade/i
      assert safe_text =~ ~r/path.*validation/i
      assert safe_text =~ ~r/safe_join/i
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns AST enhancement rules" do
      ast = Cve202133203.ast_enhancement()
      
      assert is_map(ast)
      assert Map.has_key?(ast, :min_confidence)
      assert Map.has_key?(ast, :context_rules)
      assert Map.has_key?(ast, :confidence_rules)
      assert Map.has_key?(ast, :ast_rules)
    end
    
    test "includes context rules for Django admin" do
      ast = Cve202133203.ast_enhancement()
      context = ast.context_rules
      
      assert Map.has_key?(context, :django_modules)
      assert "django.contrib.admindocs" in context.django_modules
      
      assert Map.has_key?(context, :vulnerable_views)
      assert "TemplateDetailView" in context.vulnerable_views
      
      assert Map.has_key?(context, :path_operations)
      assert "safe_join" in context.path_operations
    end
    
    test "includes confidence adjustments" do
      ast = Cve202133203.ast_enhancement()
      adjustments = ast.confidence_rules.adjustments
      
      # High confidence for vulnerable patterns
      assert adjustments.admindocs_usage > 0.7
      assert adjustments.template_detail_view > 0.8
      
      # Lower confidence in safe contexts
      assert adjustments.has_path_validation < 0
      assert adjustments.django_version_check < 0
    end
    
    test "includes AST rules for path analysis" do
      ast = Cve202133203.ast_enhancement()
      rules = ast.ast_rules
      
      assert Map.has_key?(rules, :path_analysis)
      assert rules.path_analysis.check_path_joins == true
      assert rules.path_analysis.detect_traversal_patterns == true
      assert rules.path_analysis.analyze_template_params == true
    end
  end
  
  describe "detection capabilities" do
    test "detects vulnerable admindocs URL configuration" do
      pattern = Cve202133203.pattern()
      
      vulnerable_code = """
      urlpatterns = [
          path('admin/', admin.site.urls),
          path('admin/doc/', include('django.contrib.admindocs.urls')),
      ]
      """
      
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end
    
    test "detects TemplateDetailView usage" do
      pattern = Cve202133203.pattern()
      
      vulnerable_code = """
      from django.contrib.admindocs.views import TemplateDetailView
      class CustomTemplateView(TemplateDetailView):
          pass
      """
      
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end
    
    test "detects vulnerable path operations" do
      pattern = Cve202133203.pattern()
      
      vulnerable_code = """
      template_path = os.path.join(template_dir, template_name)
      template_file = Path(template_path)
      """
      
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end
    
    test "does not match safe Django versions" do
      pattern = Cve202133203.pattern()
      
      safe_code = """
      # Django 3.2.4+ with proper path validation
      from django.utils._os import safe_join
      template_path = safe_join(template_dir, template_name)
      """
      
      # Should not trigger false positive on properly validated paths
      refute Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, "safe_join")
      end)
    end
  end
  
  describe "enhanced_pattern/0" do
    test "uses ast_enhancement" do
      enhanced = Cve202133203.enhanced_pattern()
      
      assert enhanced.id == "django-cve-2021-33203"
      assert enhanced.ast_enhancement == Cve202133203.ast_enhancement()
    end
  end
end