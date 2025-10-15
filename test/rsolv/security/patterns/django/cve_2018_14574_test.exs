defmodule Rsolv.Security.Patterns.Django.Cve201814574Test do
  use ExUnit.Case, async: true
  alias Rsolv.Security.Patterns.Django.Cve201814574

  describe "Django CVE-2018-14574 pattern" do
    test "returns correct pattern structure" do
      pattern = Cve201814574.pattern()

      assert pattern.id == "django-cve-2018-14574"
      assert pattern.name == "Django CVE-2018-14574 - Open Redirect"

      assert pattern.description ==
               "Open redirect in CommonMiddleware via APPEND_SLASH and URL redirection"

      assert pattern.type == :open_redirect
      assert pattern.severity == :medium
      assert pattern.languages == ["python"]
      assert pattern.frameworks == ["django"]
      assert pattern.cwe_id == "CWE-601"
      assert pattern.owasp_category == "A01:2021"
      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 4
    end

    test "detects APPEND_SLASH configuration" do
      pattern = Cve201814574.pattern()

      vulnerable_code = "APPEND_SLASH = True"
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end

    test "detects redirect with user input" do
      pattern = Cve201814574.pattern()

      vulnerable_code = "return redirect(request.GET['next'])"
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end

    test "detects HttpResponseRedirect with user input" do
      pattern = Cve201814574.pattern()

      vulnerable_code = "return HttpResponseRedirect(request.META.get('HTTP_REFERER'))"
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end

    test "detects CommonMiddleware usage patterns" do
      pattern = Cve201814574.pattern()

      vulnerable_codes = [
        "MIDDLEWARE = ['django.middleware.common.CommonMiddleware']",
        "from django.http import HttpResponseRedirect",
        "redirect_url = request.GET.get('url')"
      ]

      Enum.each(vulnerable_codes, fn code ->
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code))
      end)
    end

    test "detects various redirect patterns with user input" do
      pattern = Cve201814574.pattern()

      vulnerable_codes = [
        "return redirect(request.POST.get('redirect_to'))",
        "HttpResponseRedirect(request.GET['redirect'])",
        "return redirect(request.session.get('next_url'))",
        "response = HttpResponseRedirect(user_url)"
      ]

      Enum.each(vulnerable_codes, fn code ->
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code))
      end)
    end

    test "includes safe code examples" do
      pattern = Cve201814574.pattern()

      assert %{safe: safe_examples} = pattern.test_cases
      assert is_list(safe_examples)
      assert length(safe_examples) >= 2

      # Verify safe examples contain proper validation
      safe_text = Enum.join(safe_examples, " ")
      assert safe_text =~ ~r/Django.*2\.1\.2|Django.*2\.0\.9|Django.*1\.11\.16/
    end

    test "includes vulnerable code examples" do
      pattern = Cve201814574.pattern()

      assert %{vulnerable: vulnerable_examples} = pattern.test_cases
      assert is_list(vulnerable_examples)
      assert length(vulnerable_examples) >= 3

      # Verify vulnerable examples show redirect with user input
      vulnerable_text = Enum.join(vulnerable_examples, " ")
      assert vulnerable_text =~ ~r/redirect.*request\.|HttpResponseRedirect.*request\./
    end

    test "recommendation includes Django version update" do
      pattern = Cve201814574.pattern()

      assert pattern.recommendation =~ ~r/Django.*2\.1\.2|Django.*2\.0\.9|Django.*1\.11\.16/
      assert pattern.recommendation =~ ~r/validate.*url|whitelist.*url/i
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive vulnerability metadata" do
      metadata = Cve201814574.vulnerability_metadata()

      assert is_binary(metadata.description)
      assert metadata.description =~ ~r/CommonMiddleware.*APPEND_SLASH/i
      assert is_list(metadata.references)
      assert length(metadata.references) >= 4

      # Check for CVE reference
      cve_refs = Enum.filter(metadata.references, &(&1.type == :cve))
      assert length(cve_refs) >= 1
      assert Enum.any?(cve_refs, &(&1.id == "CVE-2018-14574"))

      # Check for CWE reference
      cwe_refs = Enum.filter(metadata.references, &(&1.type == :cwe))
      assert length(cwe_refs) >= 1
      assert Enum.any?(cwe_refs, &(&1.id == "CWE-601"))
    end

    test "includes attack vectors" do
      metadata = Cve201814574.vulnerability_metadata()

      assert is_list(metadata.attack_vectors)
      assert length(metadata.attack_vectors) >= 3

      attack_text = Enum.join(metadata.attack_vectors, " ")
      assert attack_text =~ ~r/phishing/i
      assert attack_text =~ ~r/redirect/i
      assert attack_text =~ ~r/malicious.*url/i
    end

    test "includes real-world impact" do
      metadata = Cve201814574.vulnerability_metadata()

      assert is_list(metadata.real_world_impact)
      assert length(metadata.real_world_impact) >= 3

      impact_text = Enum.join(metadata.real_world_impact, " ")
      assert impact_text =~ ~r/phishing.*attack/i
      assert impact_text =~ ~r/social.*engineering/i
    end

    test "includes CVE examples with severity scores" do
      metadata = Cve201814574.vulnerability_metadata()

      assert is_list(metadata.cve_examples)
      assert length(metadata.cve_examples) >= 1

      cve_example = Enum.find(metadata.cve_examples, &(&1.id == "CVE-2018-14574"))
      assert cve_example != nil
      assert cve_example.severity == "medium"
      assert cve_example.cvss == 6.1
      assert is_binary(cve_example.description)
    end

    test "includes detection notes" do
      metadata = Cve201814574.vulnerability_metadata()

      assert is_binary(metadata.detection_notes)
      assert metadata.detection_notes =~ ~r/APPEND_SLASH|CommonMiddleware/
      assert metadata.detection_notes =~ ~r/redirect|HttpResponseRedirect/i
    end

    test "includes safe alternatives" do
      metadata = Cve201814574.vulnerability_metadata()

      assert is_list(metadata.safe_alternatives)
      assert length(metadata.safe_alternatives) >= 3

      safe_text = Enum.join(metadata.safe_alternatives, " ")
      assert safe_text =~ ~r/Django.*2\.1\.2|Django.*2\.0\.9|Django.*1\.11\.16/
      assert safe_text =~ ~r/validate.*url|whitelist.*url/i
    end

    test "includes additional context" do
      metadata = Cve201814574.vulnerability_metadata()

      assert is_map(metadata.additional_context)
      assert is_list(metadata.additional_context.common_mistakes)
      assert is_list(metadata.additional_context.secure_patterns)
      assert is_list(metadata.additional_context.framework_specific_notes)

      context_text = inspect(metadata.additional_context)
      assert context_text =~ ~r/CommonMiddleware/i
      assert context_text =~ ~r/APPEND_SLASH/i
    end
  end

  describe "ast_enhancement/0" do
    test "returns valid AST enhancement structure" do
      enhancement = Cve201814574.ast_enhancement()

      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert is_list(enhancement.ast_rules)
      assert length(enhancement.ast_rules) >= 2
    end

    test "includes context rules for reducing false positives" do
      enhancement = Cve201814574.ast_enhancement()

      # Check for exclusion rules
      exclusion_rules = Enum.filter(enhancement.ast_rules, &(&1.type == :exclusion))
      assert length(exclusion_rules) >= 1

      exclusion_rule = List.first(exclusion_rules)
      assert is_list(exclusion_rule.patterns)
      assert length(exclusion_rule.patterns) >= 1
    end

    test "includes validation rules for redirect operations" do
      enhancement = Cve201814574.ast_enhancement()

      # Check for validation rules
      validation_rules = Enum.filter(enhancement.ast_rules, &(&1.type == :validation))
      assert length(validation_rules) >= 1

      validation_rule = List.first(validation_rules)
      assert is_map(validation_rule.context)
      assert Map.has_key?(validation_rule.context, :required_imports)
    end

    test "includes confidence adjustment rules" do
      enhancement = Cve201814574.ast_enhancement()

      # Check for confidence adjustment rules
      confidence_rules = Enum.filter(enhancement.ast_rules, &(&1.type == :confidence_adjustment))
      assert length(confidence_rules) >= 1

      confidence_rule = List.first(confidence_rules)
      assert is_map(confidence_rule.adjustments)
      assert Map.has_key?(confidence_rule.adjustments, :direct_user_input_to_redirect)
      assert confidence_rule.adjustments.direct_user_input_to_redirect > 0.7
    end

    test "enhanced_pattern function uses ast_enhancement" do
      enhanced = Cve201814574.enhanced_pattern()
      base = Cve201814574.pattern()

      assert enhanced.id == base.id
      assert Map.has_key?(enhanced, :ast_enhancement)
      assert enhanced.ast_enhancement == Cve201814574.ast_enhancement()
    end
  end
end
