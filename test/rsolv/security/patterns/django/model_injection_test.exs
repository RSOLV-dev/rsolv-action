defmodule Rsolv.Security.Patterns.Django.ModelInjectionTest do
  use ExUnit.Case

  alias Rsolv.Security.Patterns.Django.ModelInjection
  alias Rsolv.Security.Pattern

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = ModelInjection.pattern()

      assert pattern.id == "django-model-injection"
      assert pattern.name == "Django Model Injection"
      assert pattern.description == "Injection vulnerabilities in model operations"
      assert pattern.type == :injection
      assert pattern.severity == :high
      assert pattern.languages == ["python"]
      assert pattern.frameworks == ["django"]
      assert pattern.cwe_id == "CWE-74"
      assert pattern.owasp_category == "A03:2021"
      assert pattern.recommendation =~ "Validate and whitelist fields"
    end

    test "includes patterns for mass assignment with request data" do
      pattern = ModelInjection.pattern()

      # Model.objects.create(**request.)
      assert Enum.any?(pattern.regex, fn r ->
               Regex.match?(r, "User.objects.create(**request.POST)")
             end)

      # Model.objects.update(**request.)
      assert Enum.any?(pattern.regex, fn r ->
               Regex.match?(r, "Model.objects.update(**request.data)")
             end)

      # save(update_fields=request.)
      assert Enum.any?(pattern.regex, fn r ->
               Regex.match?(r, "model.save(update_fields=request.POST.getlist('fields'))")
             end)
    end

    test "includes patterns for dynamic attribute setting" do
      pattern = ModelInjection.pattern()

      # setattr/getattr with request data
      assert Enum.any?(pattern.regex, fn r ->
               Regex.match?(r, "setattr(user, request.POST['field'], value)")
             end)

      assert Enum.any?(pattern.regex, fn r ->
               Regex.match?(r, "getattr(model, request.GET['attr'])")
             end)
    end

    test "includes test cases for vulnerable code" do
      pattern = ModelInjection.pattern()

      assert is_list(pattern.test_cases.vulnerable)
      assert length(pattern.test_cases.vulnerable) >= 3

      # Check for mass assignment
      assert Enum.any?(pattern.test_cases.vulnerable, &(&1 =~ "**request.POST"))

      # Check for setattr usage
      assert Enum.any?(pattern.test_cases.vulnerable, &(&1 =~ "setattr"))
    end

    test "includes test cases for safe code" do
      pattern = ModelInjection.pattern()

      assert is_list(pattern.test_cases.safe)
      assert length(pattern.test_cases.safe) >= 2

      # Check for explicit field assignment
      assert Enum.any?(pattern.test_cases.safe, &(&1 =~ "username=request.POST.get('username')"))

      # Check for allowed fields filtering
      assert Enum.any?(pattern.test_cases.safe, &(&1 =~ "allowed_fields"))
    end
  end

  describe "vulnerability_metadata/0" do
    test "includes comprehensive vulnerability details" do
      metadata = ModelInjection.vulnerability_metadata()

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
      metadata = ModelInjection.vulnerability_metadata()
      references = metadata.references

      assert is_list(references)
      assert length(references) >= 3

      # Check for CWE reference
      assert Enum.any?(references, &(&1.type == :cwe && &1.id == "CWE-74"))

      # Check for OWASP reference
      assert Enum.any?(references, &(&1.type == :owasp))
    end

    test "includes attack vectors" do
      metadata = ModelInjection.vulnerability_metadata()

      assert is_list(metadata.attack_vectors)
      assert length(metadata.attack_vectors) >= 4

      # Should include various injection techniques
      vectors_text = Enum.join(metadata.attack_vectors, " ")
      assert vectors_text =~ ~r/mass.*assignment/i
      assert vectors_text =~ ~r/parameter.*manipulation/i
      assert vectors_text =~ ~r/field.*injection/i
    end

    test "includes real-world impacts" do
      metadata = ModelInjection.vulnerability_metadata()

      assert is_list(metadata.real_world_impact)
      assert length(metadata.real_world_impact) >= 4

      # Should include business impacts
      impacts_text = Enum.join(metadata.real_world_impact, " ")
      assert impacts_text =~ ~r/privilege.*escalation/i
      assert impacts_text =~ ~r/unauthorized.*modification/i
      assert impacts_text =~ ~r/data.*corruption/i
    end

    test "includes safe alternatives" do
      metadata = ModelInjection.vulnerability_metadata()

      assert is_list(metadata.safe_alternatives)
      assert length(metadata.safe_alternatives) >= 3

      # Should include specific Django model safety practices
      safe_text = Enum.join(metadata.safe_alternatives, " ")
      assert safe_text =~ ~r/ModelForm/
      assert safe_text =~ ~r/fields.*whitelist/
      assert safe_text =~ ~r/serializer/
    end
  end

  describe "ast_enhancement/0" do
    test "returns AST enhancement rules" do
      ast = ModelInjection.ast_enhancement()

      assert is_map(ast)
      assert Map.has_key?(ast, :min_confidence)
      assert Map.has_key?(ast, :context_rules)
      assert Map.has_key?(ast, :confidence_rules)
      assert Map.has_key?(ast, :ast_rules)
    end

    test "includes context rules for model operations" do
      ast = ModelInjection.ast_enhancement()
      context = ast.context_rules

      assert Map.has_key?(context, :model_methods)
      assert "objects.create" in context.model_methods
      assert "objects.update" in context.model_methods
      assert "save" in context.model_methods

      assert Map.has_key?(context, :dangerous_functions)
      assert "setattr" in context.dangerous_functions
      assert "getattr" in context.dangerous_functions

      assert Map.has_key?(context, :request_sources)
      assert "request.POST" in context.request_sources
      assert "request.data" in context.request_sources
    end

    test "includes confidence adjustments" do
      ast = ModelInjection.ast_enhancement()
      adjustments = ast.confidence_rules.adjustments

      # High confidence for direct mass assignment
      assert adjustments.mass_assignment_create > 0.9
      assert adjustments.mass_assignment_update > 0.85

      # High confidence for setattr usage
      assert adjustments.setattr_with_request > 0.9

      # Lower confidence in forms
      assert adjustments.in_model_form < 0
      assert adjustments.in_serializer < 0
    end

    test "includes AST rules for injection analysis" do
      ast = ModelInjection.ast_enhancement()
      rules = ast.ast_rules

      assert Map.has_key?(rules, :model_analysis)
      assert rules.model_analysis.detect_mass_assignment == true
      assert rules.model_analysis.check_field_validation == true
      assert rules.model_analysis.analyze_attribute_setting == true
    end
  end

  describe "detection capabilities" do
    test "detects mass assignment with request.POST" do
      pattern = ModelInjection.pattern()

      vulnerable_code = """
      def create_user(request):
          user = User.objects.create(**request.POST)
          return redirect('user_detail', user.id)
      """

      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end

    test "detects update with unpacked request data" do
      pattern = ModelInjection.pattern()

      vulnerable_code = """
      def update_profile(request):
          Profile.objects.filter(user=request.user).update(**request.data)
      """

      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end

    test "detects setattr with request data" do
      pattern = ModelInjection.pattern()

      vulnerable_code = """
      for field, value in request.POST.items():
          setattr(model, field, value)
      model.save()
      """

      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end

    test "does not match safe field assignment" do
      pattern = ModelInjection.pattern()

      safe_code = """
      def create_user(request):
          user = User.objects.create(
              username=request.POST.get('username'),
              email=request.POST.get('email')
          )
      """

      # Should not match explicit field assignment
      refute Enum.any?(pattern.regex, &Regex.match?(&1, safe_code))
    end
  end

  describe "enhanced_pattern/0" do
    test "uses ast_enhancement" do
      enhanced = ModelInjection.enhanced_pattern()

      assert enhanced.id == "django-model-injection"
      assert enhanced.ast_enhancement == ModelInjection.ast_enhancement()
    end
  end
end
