defmodule RsolvApi.Security.Patterns.Django.Cve201914234Test do
  use ExUnit.Case, async: true
  alias RsolvApi.Security.Patterns.Django.Cve201914234

  describe "Django CVE-2019-14234 pattern" do
    test "returns correct pattern structure" do
      pattern = Cve201914234.pattern()
      
      assert pattern.id == "django-cve-2019-14234"
      assert pattern.name == "Django CVE-2019-14234 - SQL Injection in JSONField"
      assert pattern.description == "SQL injection via JSONField/HStoreField key transforms due to shallow key transformation error"
      assert pattern.type == :sql_injection
      assert pattern.severity == :critical
      assert pattern.languages == ["python"]
      assert pattern.frameworks == ["django"]
      assert pattern.cwe_id == "CWE-89"
      assert pattern.owasp_category == "A03:2021"
      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 4
    end

    test "detects JSONField key lookups with user input" do
      pattern = Cve201914234.pattern()
      
      vulnerable_code = "Model.objects.filter(data__key=request.GET['key'])"
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end

    test "detects HStoreField key lookups with user input" do
      pattern = Cve201914234.pattern()
      
      vulnerable_code = "Model.objects.filter(hstore_field__somekey=request.POST['value'])"
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end

    test "detects JSONField with contains lookup" do
      pattern = Cve201914234.pattern()
      
      vulnerable_code = "queryset.filter(json_field__contains=request.POST['search'])"
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end

    test "detects nested key transforms" do
      pattern = Cve201914234.pattern()
      
      vulnerable_code = "Model.objects.filter(metadata__user__name=request.GET.get('username'))"
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end

    test "detects index-based JSONField lookups" do
      pattern = Cve201914234.pattern()
      
      vulnerable_codes = [
        "Model.objects.filter(data__0=request.GET['item'])",
        "queryset.filter(json_array__1__key=request.POST['value'])",
        "Entry.objects.filter(metadata__tags__0=user_input)"
      ]
      
      Enum.each(vulnerable_codes, fn code ->
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code))
      end)
    end

    test "detects various JSONField operations with user input" do
      pattern = Cve201914234.pattern()
      
      vulnerable_codes = [
        "Model.objects.filter(data__has_key=request.GET['key'])",
        "queryset.filter(json_field__has_keys=request.POST.getlist('keys'))",
        "Entry.objects.filter(metadata__key__isnull=False, metadata__key=user_key)"
      ]
      
      Enum.each(vulnerable_codes, fn code ->
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code))
      end)
    end

    test "includes safe code examples" do
      pattern = Cve201914234.pattern()
      
      assert %{safe: safe_examples} = pattern.test_cases
      assert is_list(safe_examples)
      assert length(safe_examples) >= 2
      
      # Verify safe examples contain proper validation or Django version updates
      safe_text = Enum.join(safe_examples, " ")
      assert safe_text =~ ~r/Django.*2\.2\.4|Django.*2\.1\.11|Django.*1\.11\.23/
    end

    test "includes vulnerable code examples" do
      pattern = Cve201914234.pattern()
      
      assert %{vulnerable: vulnerable_examples} = pattern.test_cases
      assert is_list(vulnerable_examples)
      assert length(vulnerable_examples) >= 3
      
      # Verify vulnerable examples show JSONField/HStoreField with user input
      vulnerable_text = Enum.join(vulnerable_examples, " ")
      assert vulnerable_text =~ ~r/JSONField|HStoreField|__\w+.*=.*request\./
    end

    test "recommendation includes Django version update" do
      pattern = Cve201914234.pattern()
      
      assert pattern.recommendation =~ ~r/Django.*2\.2\.4|Django.*2\.1\.11|Django.*1\.11\.23/
      assert pattern.recommendation =~ ~r/validate.*input|sanitize.*key/i
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive vulnerability metadata" do
      metadata = Cve201914234.vulnerability_metadata()
      
      assert is_binary(metadata.description)
      assert metadata.description =~ ~r/shallow.*key.*transformation/i
      assert is_list(metadata.references)
      assert length(metadata.references) >= 4
      
      # Check for CVE reference
      cve_refs = Enum.filter(metadata.references, &(&1.type == :cve))
      assert length(cve_refs) >= 1
      assert Enum.any?(cve_refs, &(&1.id == "CVE-2019-14234"))
      
      # Check for CWE reference
      cwe_refs = Enum.filter(metadata.references, &(&1.type == :cwe))
      assert length(cwe_refs) >= 1
      assert Enum.any?(cwe_refs, &(&1.id == "CWE-89"))
    end

    test "includes attack vectors" do
      metadata = Cve201914234.vulnerability_metadata()
      
      assert is_list(metadata.attack_vectors)
      assert length(metadata.attack_vectors) >= 3
      
      attack_text = Enum.join(metadata.attack_vectors, " ")
      assert attack_text =~ ~r/SQL.*injection/i
      assert attack_text =~ ~r/key.*transform/i
      assert attack_text =~ ~r/JSONField|HStoreField/
    end

    test "includes real-world impact" do
      metadata = Cve201914234.vulnerability_metadata()
      
      assert is_list(metadata.real_world_impact)
      assert length(metadata.real_world_impact) >= 3
      
      impact_text = Enum.join(metadata.real_world_impact, " ")
      assert impact_text =~ ~r/data.*breach|unauthorized.*access/i
      assert impact_text =~ ~r/database.*compromise/i
    end

    test "includes CVE examples with severity scores" do
      metadata = Cve201914234.vulnerability_metadata()
      
      assert is_list(metadata.cve_examples)
      assert length(metadata.cve_examples) >= 1
      
      cve_example = Enum.find(metadata.cve_examples, &(&1.id == "CVE-2019-14234"))
      assert cve_example != nil
      assert cve_example.severity == "critical"
      assert cve_example.cvss == 9.8
      assert is_binary(cve_example.description)
    end

    test "includes detection notes" do
      metadata = Cve201914234.vulnerability_metadata()
      
      assert is_binary(metadata.detection_notes)
      assert metadata.detection_notes =~ ~r/JSONField|HStoreField/
      assert metadata.detection_notes =~ ~r/key.*lookup|transform/i
    end

    test "includes safe alternatives" do
      metadata = Cve201914234.vulnerability_metadata()
      
      assert is_list(metadata.safe_alternatives)
      assert length(metadata.safe_alternatives) >= 3
      
      safe_text = Enum.join(metadata.safe_alternatives, " ")
      assert safe_text =~ ~r/Django.*2\.2\.4|Django.*2\.1\.11|Django.*1\.11\.23/
      assert safe_text =~ ~r/validate.*input|sanitize.*key/i
    end

    test "includes additional context" do
      metadata = Cve201914234.vulnerability_metadata()
      
      assert is_map(metadata.additional_context)
      assert is_list(metadata.additional_context.common_mistakes)
      assert is_list(metadata.additional_context.secure_patterns)
      assert is_list(metadata.additional_context.framework_specific_notes)
      
      context_text = inspect(metadata.additional_context)
      assert context_text =~ ~r/JSONField|HStoreField/
      assert context_text =~ ~r/postgres/i
    end
  end

  describe "ast_enhancement/0" do
    test "returns valid AST enhancement structure" do
      enhancement = Cve201914234.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert is_list(enhancement.ast_rules)
      assert length(enhancement.ast_rules) >= 2
    end

    test "includes context rules for reducing false positives" do
      enhancement = Cve201914234.ast_enhancement()
      
      # Check for exclusion rules
      exclusion_rules = Enum.filter(enhancement.ast_rules, &(&1.type == :exclusion))
      assert length(exclusion_rules) >= 1
      
      exclusion_rule = List.first(exclusion_rules)
      assert is_list(exclusion_rule.patterns)
      assert length(exclusion_rule.patterns) >= 1
    end

    test "includes validation rules for JSONField operations" do
      enhancement = Cve201914234.ast_enhancement()
      
      # Check for validation rules
      validation_rules = Enum.filter(enhancement.ast_rules, &(&1.type == :validation))
      assert length(validation_rules) >= 1
      
      validation_rule = List.first(validation_rules)
      assert is_map(validation_rule.context)
      assert Map.has_key?(validation_rule.context, :required_imports)
    end

    test "includes confidence adjustment rules" do
      enhancement = Cve201914234.ast_enhancement()
      
      # Check for confidence adjustment rules
      confidence_rules = Enum.filter(enhancement.ast_rules, &(&1.type == :confidence_adjustment))
      assert length(confidence_rules) >= 1
      
      confidence_rule = List.first(confidence_rules)
      assert is_map(confidence_rule.adjustments)
      assert Map.has_key?(confidence_rule.adjustments, :direct_user_input_to_jsonfield)
      assert confidence_rule.adjustments.direct_user_input_to_jsonfield > 0.8
    end

    test "enhanced_pattern function uses ast_enhancement" do
      enhanced = Cve201914234.enhanced_pattern()
      base = Cve201914234.pattern()
      
      assert enhanced.id == base.id
      assert Map.has_key?(enhanced, :ast_enhancement)
      assert enhanced.ast_enhancement == Cve201914234.ast_enhancement()
    end
  end
end