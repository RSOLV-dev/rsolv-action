defmodule Rsolv.Security.Patterns.Javascript.PathTraversalConcatTest do
  use ExUnit.Case, async: true
  
  alias Rsolv.Security.Patterns.Javascript.PathTraversalConcat
  alias Rsolv.Security.Pattern
  
  doctest PathTraversalConcat
  
  describe "PathTraversalConcat pattern" do
    test "pattern/0 returns correct structure" do
      pattern = PathTraversalConcat.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-path-traversal-concat"
      assert pattern.name == "Path Traversal via String Concatenation"
      assert pattern.description == "Building file paths with string concatenation is vulnerable to traversal attacks"
      assert pattern.type == :path_traversal
      assert pattern.severity == :high
      assert pattern.languages == ["javascript", "typescript"]
      assert pattern.cwe_id == "CWE-22"
      assert pattern.owasp_category == "A01:2021"
      assert is_binary(pattern.recommendation)
      assert is_map(pattern.test_cases)
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
    end
    
    test "pattern detects vulnerable path concatenation" do
      pattern = PathTraversalConcat.pattern()
      
      vulnerable_cases = [
        ~S|fs.readFile("./uploads/" + filename)|,
        ~S|fs.writeFile("/tmp/" + req.body.name, data)|,
        ~S|const content = fs.readFileSync(`./data/${userFile}`)|,
        ~S|readFile(baseDir + "/" + params.file)|,
        ~S|writeFileSync("/logs/" + userInput + ".log", content)|,
        ~S|fs.access(`${uploadPath}/${userFile}`, fs.constants.F_OK)|
      ]
      
      for code <- vulnerable_cases do
        assert Regex.match?(pattern.regex, code), 
          "Failed to match vulnerable code: #{code}"
      end
    end
    
    test "pattern does not match safe path concatenation" do
      pattern = PathTraversalConcat.pattern()
      
      safe_cases = [
        ~S|fs.readFile(path.join("./uploads", path.basename(filename)))|,
        ~S|const safeName = sanitizeFilename(req.body.name); fs.writeFile(path.join("/tmp", safeName), data)|,
        ~S|if (isPathSafe(userFile)) { fs.readFile(path.join("./data", userFile)) }|,
        ~S|fs.readFile("/static/images/logo.png")|,
        ~S|const configPath = path.join(__dirname, "config.json")|,
        ~S|fs.writeFile("/logs/system.log", content)|
      ]
      
      for code <- safe_cases do
        refute Regex.match?(pattern.regex, code),
          "Incorrectly matched safe code: #{code}"
      end
    end
    
    test "vulnerability_metadata/0 returns comprehensive metadata" do
      metadata = PathTraversalConcat.vulnerability_metadata()
      
      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert String.length(metadata.description) > 100
      
      # Check references structure
      assert is_list(metadata.references)
      assert length(metadata.references) >= 3
      
      for ref <- metadata.references do
        assert Map.has_key?(ref, :type)
        assert Map.has_key?(ref, :url)
        assert ref.type in [:cwe, :owasp, :research, :nist, :npm_advisory]
        assert String.starts_with?(ref.url, "http")
      end
      
      # Check attack vectors
      assert is_list(metadata.attack_vectors)
      assert length(metadata.attack_vectors) >= 3
      
      # Check real world impact
      assert is_list(metadata.real_world_impact)
      assert length(metadata.real_world_impact) >= 3
      
      # Check CVE examples
      assert is_list(metadata.cve_examples)
      assert length(metadata.cve_examples) >= 2
      
      for cve <- metadata.cve_examples do
        assert Map.has_key?(cve, :id)
        assert Map.has_key?(cve, :description)
        assert Map.has_key?(cve, :severity)
        assert String.starts_with?(cve.id, "CVE-")
        assert cve.severity in ["low", "medium", "high", "critical"]
      end
      
      # Check safe alternatives
      assert is_list(metadata.safe_alternatives)
      assert length(metadata.safe_alternatives) >= 3
      
      # Check detection notes
      assert is_binary(metadata.detection_notes)
      assert String.length(metadata.detection_notes) > 50
    end
    
    test "applies_to_file?/1 works correctly" do
      # JavaScript and TypeScript files
      assert PathTraversalConcat.applies_to_file?("test.js", nil)
      assert PathTraversalConcat.applies_to_file?("app.jsx", nil)
      assert PathTraversalConcat.applies_to_file?("server.ts", nil)
      assert PathTraversalConcat.applies_to_file?("component.tsx", nil)
      assert PathTraversalConcat.applies_to_file?("module.mjs", nil)
      
      # Non-JavaScript files
      refute PathTraversalConcat.applies_to_file?("test.py", nil)
      refute PathTraversalConcat.applies_to_file?("app.rb", nil)
      refute PathTraversalConcat.applies_to_file?("server.php", nil)
    end
    
    test "applies_to_file?/2 detects embedded file operations" do
      # Should detect file operations in any file
      content_with_file_ops = "const content = fs.readFile('./uploads/' + filename);"
      assert PathTraversalConcat.applies_to_file?("template.html", content_with_file_ops)
      
      # Should not match files without file operations
      content_without_file_ops = "console.log('Hello world');"
      refute PathTraversalConcat.applies_to_file?("template.html", content_without_file_ops)
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns comprehensive AST enhancement rules" do
      enhancement = PathTraversalConcat.ast_enhancement()
      
      assert is_map(enhancement)
      assert Enum.sort(Map.keys(enhancement)) == Enum.sort([:ast_rules, :context_rules, :confidence_rules, :min_confidence])
    end
    
    test "AST rules target string concatenation for paths" do
      enhancement = PathTraversalConcat.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "BinaryExpression"
      assert enhancement.ast_rules.operator == "+"
      assert enhancement.ast_rules.context_analysis.building_file_path == true
      assert enhancement.ast_rules.context_analysis.has_user_input == true
      assert enhancement.ast_rules.context_analysis.has_path_separators == true
    end
    
    test "context rules exclude test files and URL building" do
      enhancement = PathTraversalConcat.ast_enhancement()
      
      assert Enum.any?(enhancement.context_rules.exclude_paths, &(&1 == ~r/test/))
      assert Enum.any?(enhancement.context_rules.exclude_paths, &(&1 == ~r/spec/))
      assert enhancement.context_rules.exclude_if_url_building == true
      assert enhancement.context_rules.exclude_if_validated == true
      assert enhancement.context_rules.exclude_if_using_safe_join == true
      assert enhancement.context_rules.high_risk_patterns == ["__dirname +", "process.cwd() +", "./uploads/"]
    end
    
    test "confidence rules heavily penalize URL building" do
      enhancement = PathTraversalConcat.ast_enhancement()
      
      assert enhancement.confidence_rules.base == 0.3
      assert enhancement.confidence_rules.adjustments["dirname_plus_user_input"] == 0.5
      assert enhancement.confidence_rules.adjustments["uploads_dir_traversal"] == 0.4
      assert enhancement.confidence_rules.adjustments["has_fs_operation_nearby"] == 0.3
      assert enhancement.confidence_rules.adjustments["validated_before_use"] == -0.8
      assert enhancement.confidence_rules.adjustments["building_url_not_path"] == -0.9
      assert enhancement.confidence_rules.adjustments["using_path_join_elsewhere"] == -0.5
      assert enhancement.min_confidence == 0.7
    end
  end
  
  describe "enhanced_pattern/0" do
    test "returns pattern with AST enhancement from ast_enhancement/0" do
      enhanced = PathTraversalConcat.enhanced_pattern()
      enhancement = PathTraversalConcat.ast_enhancement()
      
      # Verify it has all the AST enhancement fields
      assert enhanced.ast_rules == enhancement.ast_rules
      assert enhanced.context_rules == enhancement.context_rules
      assert enhanced.confidence_rules == enhancement.confidence_rules
      assert enhanced.min_confidence == enhancement.min_confidence
      
      # And still has all the pattern fields
      assert enhanced.id == "js-path-traversal-concat"
      assert enhanced.severity == :high
    end
  end
end