defmodule RsolvApi.Security.Patterns.Ruby.MassAssignmentTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Ruby.MassAssignment
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = MassAssignment.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "ruby-mass-assignment"
      assert pattern.name == "Mass Assignment Vulnerability"
      assert pattern.severity == :high
      assert pattern.type == :mass_assignment
      assert pattern.languages == ["ruby"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = MassAssignment.pattern()
      
      assert pattern.cwe_id == "CWE-915"
      assert pattern.owasp_category == "A01:2021"
    end
    
    test "has multiple regex patterns" do
      pattern = MassAssignment.pattern()
      
      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 3
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = MassAssignment.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches create with params hash", %{pattern: pattern} do
      vulnerable_code = [
        "User.create(params[:user])",
        "User.create!(params[:user])",
        "user = User.create(params[:data])",
        "@post = Post.create(params[:post])"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches update methods with params", %{pattern: pattern} do
      vulnerable_code = [
        "user.update(params[:user])",
        "user.update!(params[:user])",
        "user.update_attributes(params[:user])",
        "@post.update_attributes(params[:post])"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches new with params", %{pattern: pattern} do
      vulnerable_code = [
        "user = User.new(params[:user])",
        "@account = Account.new(params[:account])",
        "Model.new(params[:model])"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches other mass assignment methods", %{pattern: pattern} do
      vulnerable_code = [
        "user.assign_attributes(params[:user])",
        "Post.insert(params[:posts])",
        "User.upsert(params[:users])"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe parameter usage", %{pattern: pattern} do
      safe_code = [
        "User.create(user_params)",
        "user.update(permitted_params)",
        "params.require(:user).permit(:name, :email)",
        "User.create(name: params[:name], email: params[:email])"
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should not match: #{code}"
      end
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = MassAssignment.vulnerability_metadata()
      
      assert metadata.description =~ "Mass assignment"
      assert length(metadata.references) >= 3
      assert length(metadata.attack_vectors) >= 3
      assert length(metadata.real_world_impact) >= 3
      assert length(metadata.cve_examples) >= 3
    end
    
    test "includes relevant CVE examples" do
      metadata = MassAssignment.vulnerability_metadata()
      
      cve_ids = Enum.map(metadata.cve_examples, & &1.id)
      assert "CVE-2020-8164" in cve_ids
      assert "CVE-2014-3514" in cve_ids
    end
    
    test "includes proper references" do
      metadata = MassAssignment.vulnerability_metadata()
      
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = MassAssignment.ast_enhancement()
      
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.7
    end
    
    test "includes Rails-specific AST rules" do
      enhancement = MassAssignment.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "MethodCall"
      assert "create" in enhancement.ast_rules.method_names
    end
    
    test "has proper parameter detection" do
      enhancement = MassAssignment.ast_enhancement()
      
      assert enhancement.context_rules.check_strong_params
      assert "permit" in enhancement.context_rules.safe_methods
    end
  end
end