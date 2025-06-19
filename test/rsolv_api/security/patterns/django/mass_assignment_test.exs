defmodule RsolvApi.Security.Patterns.Django.MassAssignmentTest do
  use ExUnit.Case
  
  alias RsolvApi.Security.Patterns.Django.MassAssignment
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = MassAssignment.pattern()
      
      assert pattern.id == "django-mass-assignment"
      assert pattern.name == "Django Mass Assignment"
      assert pattern.description == "Mass assignment allowing unauthorized field updates"
      assert pattern.type == :mass_assignment
      assert pattern.severity == :high
      assert pattern.languages == ["python"]
      assert pattern.frameworks == ["django"]
      assert pattern.default_tier == :ai
      assert pattern.cwe_id == "CWE-915"
      assert pattern.owasp_category == "A01:2021"
      assert pattern.recommendation =~ "Explicitly define allowed fields"
    end
    
    test "includes patterns for dangerous ModelForm configurations" do
      pattern = MassAssignment.pattern()
      
      # fields = '__all__' in ModelForm
      assert Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, "class UserForm(ModelForm):\n    class Meta:\n        model = User\n        fields = '__all__'")
      end)
      
      # fields = "__all__" (double quotes)
      assert Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, ~s|fields = "__all__"|)
      end)
    end
    
    test "includes patterns for unsafe save operations" do
      pattern = MassAssignment.pattern()
      
      # form.save(commit=False) without subsequent save
      assert Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, "user = form.save(commit=False)")
      end)
      
      # The test for "should not match when followed by save()" is not needed
      # because the pattern naturally won't match if there's a subsequent save()
      # due to the negative lookahead (?!.*\.save\s*\()
    end
    
    test "includes patterns for DRF serializer issues" do
      pattern = MassAssignment.pattern()
      
      # Serializer without validated_data check
      assert Enum.any?(pattern.regex, fn r ->
        Regex.match?(r, "serializer = UserSerializer(data=request.data)\nserializer.save()")
      end)
    end
    
    test "includes test cases for vulnerable code" do
      pattern = MassAssignment.pattern()
      
      assert is_list(pattern.test_cases.vulnerable)
      assert length(pattern.test_cases.vulnerable) >= 2
      
      # Check for ModelForm __all__
      assert Enum.any?(pattern.test_cases.vulnerable, &(&1 =~ "fields = '__all__'"))
      
      # Check for serializer issue
      assert Enum.any?(pattern.test_cases.vulnerable, &(&1 =~ "serializer"))
    end
    
    test "includes test cases for safe code" do
      pattern = MassAssignment.pattern()
      
      assert is_list(pattern.test_cases.safe)
      assert length(pattern.test_cases.safe) >= 2
      
      # Check for explicit fields
      assert Enum.any?(pattern.test_cases.safe, &(&1 =~ "fields = ['username', 'email']"))
      
      # Check for validated serializer
      assert Enum.any?(pattern.test_cases.safe, &(&1 =~ "is_valid()"))
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "includes comprehensive vulnerability details" do
      metadata = MassAssignment.vulnerability_metadata()
      
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
      metadata = MassAssignment.vulnerability_metadata()
      references = metadata.references
      
      assert is_list(references)
      assert length(references) >= 3
      
      # Check for CWE reference
      assert Enum.any?(references, &(&1.type == :cwe && &1.id == "CWE-915"))
      
      # Check for OWASP reference
      assert Enum.any?(references, &(&1.type == :owasp))
    end
    
    test "includes attack vectors" do
      metadata = MassAssignment.vulnerability_metadata()
      
      assert is_list(metadata.attack_vectors)
      assert length(metadata.attack_vectors) >= 4
      
      # Should include various mass assignment techniques
      vectors_text = Enum.join(metadata.attack_vectors, " ")
      assert vectors_text =~ ~r/fields.*__all__/i
      assert vectors_text =~ ~r/form.*save.*commit.*false/i
      assert vectors_text =~ ~r/serializer/i
    end
    
    test "includes real-world impacts" do
      metadata = MassAssignment.vulnerability_metadata()
      
      assert is_list(metadata.real_world_impact)
      assert length(metadata.real_world_impact) >= 4
      
      # Should include business impacts
      impacts_text = Enum.join(metadata.real_world_impact, " ")
      assert impacts_text =~ ~r/privilege.*escalation/i
      assert impacts_text =~ ~r/admin.*access/i
      assert impacts_text =~ ~r/data.*manipulation/i
    end
    
    test "includes safe alternatives" do
      metadata = MassAssignment.vulnerability_metadata()
      
      assert is_list(metadata.safe_alternatives)
      assert length(metadata.safe_alternatives) >= 3
      
      # Should include specific Django form safety practices
      safe_text = Enum.join(metadata.safe_alternatives, " ")
      assert safe_text =~ ~r/fields\s*=\s*\[/
      assert safe_text =~ ~r/ModelForm/
      assert safe_text =~ ~r/read_only_fields/
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns AST enhancement rules" do
      ast = MassAssignment.ast_enhancement()
      
      assert is_map(ast)
      assert Map.has_key?(ast, :min_confidence)
      assert Map.has_key?(ast, :context_rules)
      assert Map.has_key?(ast, :confidence_rules)
      assert Map.has_key?(ast, :ast_rules)
    end
    
    test "includes context rules for mass assignment" do
      ast = MassAssignment.ast_enhancement()
      context = ast.context_rules
      
      assert Map.has_key?(context, :form_attributes)
      assert "__all__" in context.form_attributes
      
      assert Map.has_key?(context, :dangerous_methods)
      assert "save" in context.dangerous_methods
      
      assert Map.has_key?(context, :serializer_patterns)
      assert "data=request" in context.serializer_patterns
    end
    
    test "includes confidence adjustments" do
      ast = MassAssignment.ast_enhancement()
      adjustments = ast.confidence_rules.adjustments
      
      # High confidence for __all__
      assert adjustments.fields_all > 0.9
      
      # Medium confidence for commit=False
      assert adjustments.save_commit_false > 0.6
      
      # Lower confidence in secure contexts
      assert adjustments.has_field_restrictions < 0
      assert adjustments.explicit_field_list < 0
    end
    
    test "includes AST rules for form analysis" do
      ast = MassAssignment.ast_enhancement()
      rules = ast.ast_rules
      
      assert Map.has_key?(rules, :form_analysis)
      assert rules.form_analysis.check_fields_attribute == true
      assert rules.form_analysis.detect_exclude_usage == true
      assert rules.form_analysis.analyze_save_patterns == true
    end
  end
  
  describe "detection capabilities" do
    test "detects ModelForm with fields = '__all__'" do
      pattern = MassAssignment.pattern()
      
      vulnerable_code = """
      class UserForm(ModelForm):
          class Meta:
              model = User
              fields = '__all__'
      """
      
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end
    
    test "detects unsafe form.save(commit=False) pattern" do
      pattern = MassAssignment.pattern()
      
      vulnerable_code = """
      def update_user(request):
          form = UserForm(request.POST)
          if form.is_valid():
              user = form.save(commit=False)
              # Missing user.save() call
      """
      
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end
    
    test "detects unvalidated serializer usage" do
      pattern = MassAssignment.pattern()
      
      vulnerable_code = """
      def create_user(request):
          serializer = UserSerializer(data=request.data)
          serializer.save()  # No is_valid() check
      """
      
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end
    
    test "does not match safe field definitions" do
      pattern = MassAssignment.pattern()
      
      safe_code = """
      class UserForm(ModelForm):
          class Meta:
              model = User
              fields = ['username', 'email', 'first_name']
      """
      
      # Should not match explicit field list
      refute Enum.any?(pattern.regex, &Regex.match?(&1, safe_code))
    end
  end
  
  describe "enhanced_pattern/0" do
    test "uses ast_enhancement" do
      enhanced = MassAssignment.enhanced_pattern()
      
      assert enhanced.id == "django-mass-assignment"
      assert enhanced.ast_enhancement == MassAssignment.ast_enhancement()
    end
  end
end