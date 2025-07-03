defmodule Rsolv.Security.Patterns.Django.Cve202013254Test do
  use ExUnit.Case, async: true
  alias Rsolv.Security.Patterns.Django.Cve202013254

  describe "Django CVE-2020-13254 pattern" do
    test "returns correct pattern structure" do
      pattern = Cve202013254.pattern()
      
      assert pattern.id == "django-cve-2020-13254"
      assert pattern.name == "Django CVE-2020-13254 - Cache Key Injection"
      assert pattern.description == "Malformed cache keys can lead to data leakage via key collision in memcached backend"
      assert pattern.type == :information_disclosure
      assert pattern.severity == :medium
      assert pattern.languages == ["python"]
      assert pattern.frameworks == ["django"]
      assert pattern.cwe_id == "CWE-74"
      assert pattern.owasp_category == "A03:2021"
      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 3
    end

    test "detects cache.set with user input" do
      pattern = Cve202013254.pattern()
      
      vulnerable_code = "cache.set(request.GET['key'], value)"
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end

    test "detects cache.get with user input" do
      pattern = Cve202013254.pattern()
      
      vulnerable_code = "cache.get(request.POST['cache_key'])"
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end

    test "detects make_key with user input" do
      pattern = Cve202013254.pattern()
      
      vulnerable_code = "make_key(request.GET.get('key'))"
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end

    test "detects memcached usage with user-controlled keys" do
      pattern = Cve202013254.pattern()
      
      vulnerable_code = """
      from django.core.cache import cache
      user_key = request.GET.get('cache_key')
      cache.set(user_key, sensitive_data)
      """
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end

    test "detects cache operations in views with malformed keys" do
      pattern = Cve202013254.pattern()
      
      vulnerable_code = """
      def view(request):
          key = request.POST['key']  # Could contain spaces, newlines
          cache.set(key, data)
      """
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end

    test "detects multiple cache backend usage patterns" do
      pattern = Cve202013254.pattern()
      
      vulnerable_codes = [
        "cache.set(request.user.username + '_' + request.GET['suffix'], data)",
        "cache.get(f'{request.META[\"REMOTE_ADDR\"]}_{request.GET[\"id\"]}')",
        "cache.delete(request.session.get('cache_key'))"
      ]
      
      Enum.each(vulnerable_codes, fn code ->
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code))
      end)
    end

    test "includes safe code examples" do
      pattern = Cve202013254.pattern()
      
      assert %{safe: safe_examples} = pattern.test_cases
      assert is_list(safe_examples)
      assert length(safe_examples) >= 2
      
      # Verify safe examples contain proper key validation
      safe_text = Enum.join(safe_examples, " ")
      assert safe_text =~ ~r/hashlib|MD5|safe_key|validate/i
    end

    test "includes vulnerable code examples" do
      pattern = Cve202013254.pattern()
      
      assert %{vulnerable: vulnerable_examples} = pattern.test_cases
      assert is_list(vulnerable_examples)
      assert length(vulnerable_examples) >= 3
      
      # Verify vulnerable examples show cache operations with user input
      vulnerable_text = Enum.join(vulnerable_examples, " ")
      assert vulnerable_text =~ ~r/cache\.set.*request\.|cache\.get.*request\./
    end

    test "recommendation includes Django version update" do
      pattern = Cve202013254.pattern()
      
      assert pattern.recommendation =~ ~r/Django.*3\.0\.7|Django.*2\.2\.13/
      assert pattern.recommendation =~ ~r/validate.*key/i
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive vulnerability metadata" do
      metadata = Cve202013254.vulnerability_metadata()
      
      assert is_binary(metadata.description)
      assert metadata.description =~ ~r/memcached.*key.*validation/i
      assert is_list(metadata.references)
      assert length(metadata.references) >= 4
      
      # Check for CVE reference
      cve_refs = Enum.filter(metadata.references, &(&1.type == :cve))
      assert length(cve_refs) >= 1
      assert Enum.any?(cve_refs, &(&1.id == "CVE-2020-13254"))
      
      # Check for CWE reference
      cwe_refs = Enum.filter(metadata.references, &(&1.type == :cwe))
      assert length(cwe_refs) >= 1
      assert Enum.any?(cwe_refs, &(&1.id == "CWE-74"))
    end

    test "includes attack vectors" do
      metadata = Cve202013254.vulnerability_metadata()
      
      assert is_list(metadata.attack_vectors)
      assert length(metadata.attack_vectors) >= 3
      
      attack_text = Enum.join(metadata.attack_vectors, " ")
      assert attack_text =~ ~r/key.*collision/i
      assert attack_text =~ ~r/data.*leakage/i
      assert attack_text =~ ~r/memcached/i
    end

    test "includes real-world impact" do
      metadata = Cve202013254.vulnerability_metadata()
      
      assert is_list(metadata.real_world_impact)
      assert length(metadata.real_world_impact) >= 3
      
      impact_text = Enum.join(metadata.real_world_impact, " ")
      assert impact_text =~ ~r/sensitive.*data/i
      assert impact_text =~ ~r/cache.*pollution/i
    end

    test "includes CVE examples with severity scores" do
      metadata = Cve202013254.vulnerability_metadata()
      
      assert is_list(metadata.cve_examples)
      assert length(metadata.cve_examples) >= 1
      
      cve_example = Enum.find(metadata.cve_examples, &(&1.id == "CVE-2020-13254"))
      assert cve_example != nil
      assert cve_example.severity == "medium"
      assert cve_example.cvss == 5.9
      assert is_binary(cve_example.description)
    end

    test "includes detection notes" do
      metadata = Cve202013254.vulnerability_metadata()
      
      assert is_binary(metadata.detection_notes)
      assert metadata.detection_notes =~ ~r/cache\.set|cache\.get/
      assert metadata.detection_notes =~ ~r/user.*input|request\./i
    end

    test "includes safe alternatives" do
      metadata = Cve202013254.vulnerability_metadata()
      
      assert is_list(metadata.safe_alternatives)
      assert length(metadata.safe_alternatives) >= 3
      
      safe_text = Enum.join(metadata.safe_alternatives, " ")
      assert safe_text =~ ~r/Django.*3\.0\.7|Django.*2\.2\.13/
      assert safe_text =~ ~r/validate.*key|sanitize.*key/i
    end

    test "includes additional context" do
      metadata = Cve202013254.vulnerability_metadata()
      
      assert is_map(metadata.additional_context)
      assert is_list(metadata.additional_context.common_mistakes)
      assert is_list(metadata.additional_context.secure_patterns)
      assert is_list(metadata.additional_context.framework_specific_notes)
      
      context_text = inspect(metadata.additional_context)
      assert context_text =~ ~r/memcached/i
      assert context_text =~ ~r/key.*validation/i
    end
  end

  describe "ast_enhancement/0" do
    test "returns valid AST enhancement structure" do
      enhancement = Cve202013254.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert is_list(enhancement.ast_rules)
      assert length(enhancement.ast_rules) >= 2
    end

    test "includes context rules for reducing false positives" do
      enhancement = Cve202013254.ast_enhancement()
      
      # Check for exclusion rules
      exclusion_rules = Enum.filter(enhancement.ast_rules, &(&1.type == :exclusion))
      assert length(exclusion_rules) >= 1
      
      exclusion_rule = List.first(exclusion_rules)
      assert is_list(exclusion_rule.patterns)
      assert length(exclusion_rule.patterns) >= 1
    end

    test "includes validation rules for cache operations" do
      enhancement = Cve202013254.ast_enhancement()
      
      # Check for validation rules
      validation_rules = Enum.filter(enhancement.ast_rules, &(&1.type == :validation))
      assert length(validation_rules) >= 1
      
      validation_rule = List.first(validation_rules)
      assert is_map(validation_rule.context)
      assert Map.has_key?(validation_rule.context, :required_imports)
    end

    test "includes confidence adjustment rules" do
      enhancement = Cve202013254.ast_enhancement()
      
      # Check for confidence adjustment rules
      confidence_rules = Enum.filter(enhancement.ast_rules, &(&1.type == :confidence_adjustment))
      assert length(confidence_rules) >= 1
      
      confidence_rule = List.first(confidence_rules)
      assert is_map(confidence_rule.adjustments)
      assert Map.has_key?(confidence_rule.adjustments, :direct_user_input_to_cache)
      assert confidence_rule.adjustments.direct_user_input_to_cache > 0.6
    end

    test "enhanced_pattern function uses ast_enhancement" do
      enhanced = Cve202013254.enhanced_pattern()
      base = Cve202013254.pattern()
      
      assert enhanced.id == base.id
      assert Map.has_key?(enhanced, :ast_enhancement)
      assert enhanced.ast_enhancement == Cve202013254.ast_enhancement()
    end
  end
end