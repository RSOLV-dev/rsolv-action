defmodule Rsolv.Security.Patterns.Ruby.PathTraversalTest do
  use ExUnit.Case, async: true
  
  alias Rsolv.Security.Patterns.Ruby.PathTraversal
  alias Rsolv.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = PathTraversal.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "ruby-path-traversal"
      assert pattern.name == "Path Traversal"
      assert pattern.severity == :high
      assert pattern.type == :path_traversal
      assert pattern.languages == ["ruby"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = PathTraversal.pattern()
      
      assert pattern.cwe_id == "CWE-22"
      assert pattern.owasp_category == "A01:2021"
    end
    
    test "has multiple regex patterns" do
      pattern = PathTraversal.pattern()
      
      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 5
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = PathTraversal.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches File.read with params", %{pattern: pattern} do
      vulnerable_code = [
        "File.read(params[:file])",
        "File.read(params[:filename])",
        "File.read(params['document'])",
        "File.read(request.params[:path])",
        "File.read(@user_file)"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches File.open with string interpolation", %{pattern: pattern} do
      vulnerable_code = [
        "File.open(\"uploads/\#{params[:file]}\")",
        "File.open(\"/tmp/\#{user_input}\")",
        "File.open(\"data/\#{params['name']}.txt\")",
        "File.open(\"logs/\#{@filename}\")"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches send_file with user input", %{pattern: pattern} do
      vulnerable_code = [
        "send_file params[:file]",
        "send_file params[:download]",
        "send_file user_requested_file",
        "send_file @document_path",
        "send_file request.params[:attachment]"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches File.join with params", %{pattern: pattern} do
      vulnerable_code = [
        "File.read(File.join(Rails.root, params[:path]))",
        "File.open(File.join('/uploads', params[:file]))",
        "send_file File.join(base_path, params[:document])",
        "File.read(File.join(directory, user_input))"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches IO.read and other file operations", %{pattern: pattern} do
      vulnerable_code = [
        "IO.read(params[:file])",
        "File.readlines(params[:log])",
        "File.write(params[:path], data)",
        "File.binread(user_path)",
        "File.exist?(params[:check])"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches Rails render with file option", %{pattern: pattern} do
      vulnerable_code = [
        "render file: params[:template]",
        "render file: \"\#{params[:view]}.html\"",
        "render file: user_template",
        "render file: request.params[:custom]"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe file operations", %{pattern: pattern} do
      safe_code = [
        "File.read('config/database.yml')",
        "File.open('/tmp/static_file.txt')",
        "send_file Rails.root.join('public', 'robots.txt')",
        "filename = File.basename(params[:file])\nFile.read(File.join(SAFE_DIR, filename))",
        "render file: 'shared/404'",
        "File.exist?('Gemfile')"
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should not match: #{code}"
      end
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = PathTraversal.vulnerability_metadata()
      
      assert metadata.description =~ "Path traversal"
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 5
      assert length(metadata.real_world_impact) >= 3
      assert length(metadata.cve_examples) >= 4
    end
    
    test "includes CVE examples from research" do
      metadata = PathTraversal.vulnerability_metadata()
      
      cve_ids = Enum.map(metadata.cve_examples, & &1.id)
      assert Enum.any?(cve_ids, &String.contains?(&1, "CVE-2019-5418"))
      assert Enum.any?(cve_ids, &String.contains?(&1, "CVE-2018-3760"))
      assert Enum.any?(cve_ids, &String.contains?(&1, "CVE-2014-0130"))
      assert Enum.any?(cve_ids, &String.contains?(&1, "CVE-2025-27610"))
    end
    
    test "includes proper security references" do
      metadata = PathTraversal.vulnerability_metadata()
      
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = PathTraversal.ast_enhancement()
      
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.7
    end
    
    test "includes file operation analysis" do
      enhancement = PathTraversal.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert enhancement.ast_rules.file_operations.check_file_methods
      assert enhancement.ast_rules.file_operations.file_methods
      assert enhancement.ast_rules.file_operations.path_methods
    end
    
    test "has user input detection" do
      enhancement = PathTraversal.ast_enhancement()
      
      assert "params" in enhancement.ast_rules.user_input_analysis.input_sources
      assert "request" in enhancement.ast_rules.user_input_analysis.input_sources
      assert enhancement.ast_rules.user_input_analysis.check_path_arguments
    end
    
    test "includes path validation checks" do
      enhancement = PathTraversal.ast_enhancement()
      
      assert enhancement.ast_rules.validation_analysis.check_path_validation
      assert enhancement.ast_rules.validation_analysis.safe_methods
      assert enhancement.ast_rules.validation_analysis.path_checks
    end
  end
end