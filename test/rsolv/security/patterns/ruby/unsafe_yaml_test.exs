defmodule Rsolv.Security.Patterns.Ruby.UnsafeYamlTest do
  use ExUnit.Case, async: true
  
  alias Rsolv.Security.Patterns.Ruby.UnsafeYaml
  alias Rsolv.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = UnsafeYaml.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "ruby-unsafe-yaml"
      assert pattern.name == "Unsafe YAML Loading"
      assert pattern.severity == :critical
      assert pattern.type == :deserialization
      assert pattern.languages == ["ruby"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = UnsafeYaml.pattern()
      
      assert pattern.cwe_id == "CWE-502"
      assert pattern.owasp_category == "A08:2021"
    end
    
    test "has multiple regex patterns" do
      pattern = UnsafeYaml.pattern()
      
      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 6
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = UnsafeYaml.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches YAML.load with params", %{pattern: pattern} do
      vulnerable_code = [
        ~S|data = YAML.load(params[:config])|,
        ~S|config = YAML.load(params["data"])|,
        ~S|obj = YAML.load(params[:yaml])|,
        ~S|result = YAML.load(params.fetch(:content))|,
        ~S|YAML.load(params[:settings])|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches YAML.load with request data", %{pattern: pattern} do
      vulnerable_code = [
        ~S|data = YAML.load(request.body.read)|,
        ~S|config = YAML.load(request.raw_post)|,
        ~S|obj = YAML.load(request.headers['X-Config'])|,
        ~S|YAML.load(request.env['HTTP_X_DATA'])|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches YAML.load with user input variables", %{pattern: pattern} do
      vulnerable_code = [
        ~S|data = YAML.load(user_input)|,
        ~S|config = YAML.load(untrusted_data)|,
        ~S|obj = YAML.load(external_data)|,
        ~S|YAML.load(client_data)|,
        ~S|result = YAML.load(uploaded_content)|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches YAML.load with file operations", %{pattern: pattern} do
      vulnerable_code = [
        ~S|config = YAML.load(File.read(params[:file]))|,
        ~S|data = YAML.load(uploaded_file.read)|,
        ~S|obj = YAML.load(File.open(user_path).read)|,
        ~S|YAML.load(IO.read(params[:config_file]))|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches Psych.load with user input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|data = Psych.load(params[:config])|,
        ~S|config = Psych.load(user_input)|,
        ~S|obj = Psych.load(request.body.read)|,
        ~S|Psych.load(uploaded_file.read)|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches Rails CVE-2013-0156 patterns", %{pattern: pattern} do
      vulnerable_code = [
        ~S|YAML::load(params[:yaml])|,
        ~S|Psych::load(params[:data])|,
        ~S|data = YAML::load(request.body)|,
        ~S|config = Psych::load(request.raw_post)|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe YAML usage", %{pattern: pattern} do
      safe_code = [
        ~S|data = YAML.safe_load(params[:config])|,
        ~S|config = YAML.safe_load(user_input, permitted_classes: [Symbol])|,
        ~S|obj = Psych.safe_load(params[:data])|,
        ~S|result = YAML.load_file("config/settings.yml")|,
        ~S|YAML.dump(user_object)|,
        ~S|JSON.parse(params[:data])|,
        ~S|config = Rails.application.config_for(:database)|
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should not match: #{code}"
      end
    end
    
    test "documents regex limitations for comment detection", %{pattern: pattern} do
      # Note: Regex patterns have known limitations with comment detection
      # This is acceptable as AST enhancement will handle such cases
      commented_code = ~S|# YAML.load(params[:data]) # Vulnerable but commented|
      
      # This is a known limitation - regex will match commented code
      assert Enum.any?(pattern.regex, &Regex.match?(&1, commented_code)),
             "Regex patterns are expected to match commented code (AST enhancement handles this)"
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = UnsafeYaml.vulnerability_metadata()
      
      assert metadata.description =~ "YAML"
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 5
      assert length(metadata.real_world_impact) >= 3
      assert length(metadata.cve_examples) >= 3
    end
    
    test "includes CVE examples from research" do
      metadata = UnsafeYaml.vulnerability_metadata()
      
      cve_ids = Enum.map(metadata.cve_examples, & &1.id)
      assert Enum.any?(cve_ids, &String.contains?(&1, "CVE-2013-0156"))
      assert Enum.any?(cve_ids, &String.contains?(&1, "CVE-2022-47986"))
    end
    
    test "includes proper references" do
      metadata = UnsafeYaml.vulnerability_metadata()
      
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = UnsafeYaml.ast_enhancement()
      
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.8
    end
    
    test "includes YAML-specific AST rules" do
      enhancement = UnsafeYaml.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert enhancement.ast_rules.yaml_analysis.yaml_libraries
      assert enhancement.ast_rules.yaml_analysis.unsafe_methods
    end
    
    test "has user input source detection" do
      enhancement = UnsafeYaml.ast_enhancement()
      
      assert "params" in enhancement.ast_rules.user_input_analysis.input_sources
      assert "request" in enhancement.ast_rules.user_input_analysis.input_sources
      assert "user_input" in enhancement.ast_rules.user_input_analysis.input_sources
    end
    
    test "includes safe vs unsafe method detection" do
      enhancement = UnsafeYaml.ast_enhancement()
      
      assert "YAML.load" in enhancement.ast_rules.yaml_analysis.unsafe_methods
      assert "YAML.safe_load" in enhancement.ast_rules.yaml_analysis.safe_methods
    end
  end
end