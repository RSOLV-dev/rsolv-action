defmodule Rsolv.Security.Patterns.Django.Cve202133571Test do
  use ExUnit.Case, async: true
  alias Rsolv.Security.Patterns.Django.Cve202133571

  describe "Django CVE-2021-33571 pattern" do
    test "returns correct pattern structure" do
      pattern = Cve202133571.pattern()

      assert pattern.id == "django-cve-2021-33571"
      assert pattern.name == "Django CVE-2021-33571 - IPv4 Validation Bypass"

      assert pattern.description ==
               "IPv4 addresses with leading zeros can bypass validation in URLValidator and validate_ipv4_address"

      assert pattern.type == :input_validation
      assert pattern.severity == :high
      assert pattern.languages == ["python"]
      assert pattern.frameworks == ["django"]
      assert pattern.cwe_id == "CWE-20"
      assert pattern.owasp_category == "A03:2021"
      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 3
    end

    test "detects URLValidator without schemes restriction" do
      pattern = Cve202133571.pattern()

      vulnerable_code = "URLValidator()(user_url)"
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end

    test "detects validate_ipv4_address with user input" do
      pattern = Cve202133571.pattern()

      vulnerable_code = "validate_ipv4_address(request.GET['ip'])"
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end

    test "detects URLValidator accepting octal IPv4 addresses" do
      pattern = Cve202133571.pattern()

      vulnerable_code = """
      from django.core.validators import URLValidator
      validator = URLValidator()
      validator('http://0177.0.0.1/')  # 0177 = 127 in octal
      """

      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end

    test "detects validate_ipv46_address vulnerability" do
      pattern = Cve202133571.pattern()

      vulnerable_code = "validate_ipv46_address(request.POST.get('address'))"
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end

    test "detects direct usage of affected Django versions" do
      pattern = Cve202133571.pattern()

      vulnerable_code = """
      # Django 3.2.3 has this vulnerability
      from django.core.validators import validate_ipv4_address
      ip = request.GET.get('ip_address')
      validate_ipv4_address(ip)
      """

      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end

    test "includes safe code examples" do
      pattern = Cve202133571.pattern()

      assert %{safe: safe_examples} = pattern.test_cases
      assert is_list(safe_examples)
      assert length(safe_examples) >= 2

      # Verify safe examples contain updated Django version guidance
      safe_text = Enum.join(safe_examples, " ")
      assert safe_text =~ ~r/Django.*3\.2\.4|Django.*3\.1\.12|Django.*2\.2\.24/i
    end

    test "includes vulnerable code examples" do
      pattern = Cve202133571.pattern()

      assert %{vulnerable: vulnerable_examples} = pattern.test_cases
      assert is_list(vulnerable_examples)
      assert length(vulnerable_examples) >= 3

      # Verify vulnerable examples show the actual vulnerability
      vulnerable_text = Enum.join(vulnerable_examples, " ")
      assert vulnerable_text =~ ~r/URLValidator|validate_ipv4_address|validate_ipv46_address/
    end

    test "recommendation includes Django version update" do
      pattern = Cve202133571.pattern()

      assert pattern.recommendation =~ ~r/Django.*3\.2\.4|Django.*3\.1\.12|Django.*2\.2\.24/
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive vulnerability metadata" do
      metadata = Cve202133571.vulnerability_metadata()

      assert is_binary(metadata.description)
      assert metadata.description =~ ~r/leading zero.*octal/i
      assert is_list(metadata.references)
      assert length(metadata.references) >= 4

      # Check for CVE reference
      cve_refs = Enum.filter(metadata.references, &(&1.type == :cve))
      assert length(cve_refs) >= 1
      assert Enum.any?(cve_refs, &(&1.id == "CVE-2021-33571"))

      # Check for CWE reference
      cwe_refs = Enum.filter(metadata.references, &(&1.type == :cwe))
      assert length(cwe_refs) >= 1
      assert Enum.any?(cwe_refs, &(&1.id == "CWE-20"))
    end

    test "includes attack vectors" do
      metadata = Cve202133571.vulnerability_metadata()

      assert is_list(metadata.attack_vectors)
      assert length(metadata.attack_vectors) >= 3

      attack_text = Enum.join(metadata.attack_vectors, " ")
      assert attack_text =~ ~r/SSRF|Server.Side.Request.Forgery/i
      assert attack_text =~ ~r/RFI|Remote.File.Inclusion/i
      assert attack_text =~ ~r/LFI|Local.File.Inclusion/i
    end

    test "includes real-world impact" do
      metadata = Cve202133571.vulnerability_metadata()

      assert is_list(metadata.real_world_impact)
      assert length(metadata.real_world_impact) >= 3

      impact_text = Enum.join(metadata.real_world_impact, " ")
      assert impact_text =~ ~r/access.*control.*bypass/i
      assert impact_text =~ ~r/network.*access/i
    end

    test "includes CVE examples with severity scores" do
      metadata = Cve202133571.vulnerability_metadata()

      assert is_list(metadata.cve_examples)
      assert length(metadata.cve_examples) >= 1

      cve_example = Enum.find(metadata.cve_examples, &(&1.id == "CVE-2021-33571"))
      assert cve_example != nil
      assert cve_example.severity == "high"
      assert cve_example.cvss == 7.5
      assert is_binary(cve_example.description)
    end

    test "includes detection notes" do
      metadata = Cve202133571.vulnerability_metadata()

      assert is_binary(metadata.detection_notes)
      assert metadata.detection_notes =~ ~r/URLValidator|validate_ipv4_address/
      assert metadata.detection_notes =~ ~r/leading.zero/i
    end

    test "includes safe alternatives" do
      metadata = Cve202133571.vulnerability_metadata()

      assert is_list(metadata.safe_alternatives)
      assert length(metadata.safe_alternatives) >= 3

      safe_text = Enum.join(metadata.safe_alternatives, " ")
      assert safe_text =~ ~r/Django.*3\.2\.4|Django.*3\.1\.12|Django.*2\.2\.24/
      assert safe_text =~ ~r/input.*validation|validation.*check/i
    end

    test "includes additional context" do
      metadata = Cve202133571.vulnerability_metadata()

      assert is_map(metadata.additional_context)
      assert is_list(metadata.additional_context.common_mistakes)
      assert is_list(metadata.additional_context.secure_patterns)
      assert is_list(metadata.additional_context.framework_specific_notes)

      context_text = inspect(metadata.additional_context)
      assert context_text =~ ~r/octal.*literal/i
      assert context_text =~ ~r/URLValidator|validate_ipv4_address/
    end
  end

  describe "ast_enhancement/0" do
    test "returns valid AST enhancement structure" do
      enhancement = Cve202133571.ast_enhancement()

      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert is_list(enhancement.ast_rules)
      assert length(enhancement.ast_rules) >= 2
    end

    test "includes context rules for reducing false positives" do
      enhancement = Cve202133571.ast_enhancement()

      # Check for exclusion rules
      exclusion_rules = Enum.filter(enhancement.ast_rules, &(&1.type == :exclusion))
      assert length(exclusion_rules) >= 1

      exclusion_rule = List.first(exclusion_rules)
      assert is_list(exclusion_rule.patterns)
      assert length(exclusion_rule.patterns) >= 1
    end

    test "includes validation rules for vulnerable patterns" do
      enhancement = Cve202133571.ast_enhancement()

      # Check for validation rules
      validation_rules = Enum.filter(enhancement.ast_rules, &(&1.type == :validation))
      assert length(validation_rules) >= 1

      validation_rule = List.first(validation_rules)
      assert is_map(validation_rule.context)
      assert Map.has_key?(validation_rule.context, :required_imports)
    end

    test "includes confidence adjustment rules" do
      enhancement = Cve202133571.ast_enhancement()

      # Check for confidence adjustment rules
      confidence_rules = Enum.filter(enhancement.ast_rules, &(&1.type == :confidence_adjustment))
      assert length(confidence_rules) >= 1

      confidence_rule = List.first(confidence_rules)
      assert is_map(confidence_rule.adjustments)
      assert Map.has_key?(confidence_rule.adjustments, :urlvalidator_without_schemes)
      assert confidence_rule.adjustments.urlvalidator_without_schemes > 0.5
    end

    test "enhanced_pattern function uses ast_enhancement" do
      enhanced = Cve202133571.enhanced_pattern()
      base = Cve202133571.pattern()

      assert enhanced.id == base.id
      assert Map.has_key?(enhanced, :ast_enhancement)
      assert enhanced.ast_enhancement == Cve202133571.ast_enhancement()
    end
  end
end
