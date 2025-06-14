defmodule RsolvApi.Security.Patterns.Javascript.PathTraversalJoinTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Javascript.PathTraversalJoin
  alias RsolvApi.Security.Pattern
  
  doctest PathTraversalJoin
  
  describe "PathTraversalJoin pattern" do
    test "pattern/0 returns correct structure" do
      pattern = PathTraversalJoin.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-path-traversal-join"
      assert pattern.name == "Path Traversal via path.join"
      assert pattern.description == "Using path.join with user input can lead to directory traversal"
      assert pattern.type == :path_traversal
      assert pattern.severity == :high
      assert pattern.languages == ["javascript", "typescript"]
      assert pattern.default_tier == :protected
      assert pattern.cwe_id == "CWE-22"
      assert pattern.owasp_category == "A01:2021"
      assert is_binary(pattern.recommendation)
      assert is_map(pattern.test_cases)
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
    end
    
    test "pattern detects vulnerable path.join calls" do
      pattern = PathTraversalJoin.pattern()
      
      vulnerable_cases = [
        ~S|path.join("/uploads", req.params.filename)|,
        ~S|const file = path.join(baseDir, userInput)|,
        ~S|fs.readFile(path.join("./data", req.query.file))|,
        ~S|const fullPath = path.join(rootDir, request.body.path)|,
        ~S|path.join(staticDir, params.file)|,
        ~S|join("/tmp", userData)|
      ]
      
      for code <- vulnerable_cases do
        assert Regex.match?(pattern.regex, code), 
          "Failed to match vulnerable code: #{code}"
      end
    end
    
    test "pattern does not match safe path.join usage" do
      pattern = PathTraversalJoin.pattern()
      
      safe_cases = [
        ~S|const safePath = path.join("/uploads", path.basename(filename))|,
        ~S|if (resolvedPath.startsWith(baseDir)) { /* safe */ }|,
        ~S|const file = path.join(baseDir, sanitize(userInput))|,
        ~S|path.join("/static", "images", "logo.png")|,
        ~S|const configPath = path.join(__dirname, "config.json")|,
        ~S|join(baseDir, validatedPath)|
      ]
      
      for code <- safe_cases do
        refute Regex.match?(pattern.regex, code),
          "Incorrectly matched safe code: #{code}"
      end
    end
    
    test "vulnerability_metadata/0 returns comprehensive metadata" do
      metadata = PathTraversalJoin.vulnerability_metadata()
      
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
      assert PathTraversalJoin.applies_to_file?("test.js")
      assert PathTraversalJoin.applies_to_file?("app.jsx")
      assert PathTraversalJoin.applies_to_file?("server.ts")
      assert PathTraversalJoin.applies_to_file?("component.tsx")
      assert PathTraversalJoin.applies_to_file?("module.mjs")
      
      # Non-JavaScript files
      refute PathTraversalJoin.applies_to_file?("test.py")
      refute PathTraversalJoin.applies_to_file?("app.rb")
      refute PathTraversalJoin.applies_to_file?("server.php")
    end
    
    test "applies_to_file?/2 detects embedded path operations" do
      # Should detect path operations in any file
      content_with_path_join = "const filePath = path.join(baseDir, userFile);"
      assert PathTraversalJoin.applies_to_file?("template.html", content_with_path_join)
      
      # Should not match files without path operations
      content_without_path = "console.log('Hello world');"
      refute PathTraversalJoin.applies_to_file?("template.html", content_without_path)
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns comprehensive AST enhancement rules" do
      enhancement = PathTraversalJoin.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.keys(enhancement) == [:ast_rules, :context_rules, :confidence_rules, :min_confidence]
    end
    
    test "AST rules target path.join call expressions" do
      enhancement = PathTraversalJoin.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert enhancement.ast_rules.callee.object == "path"
      assert enhancement.ast_rules.callee.property == "join"
      assert enhancement.ast_rules.callee.alternatives == ["resolve", "normalize"]
      assert enhancement.ast_rules.argument_analysis.has_user_controlled_path == true
      assert enhancement.ast_rules.argument_analysis.not_validated == true
      assert enhancement.ast_rules.argument_analysis.contains_traversal_sequences == true
    end
    
    test "context rules exclude test files and safe patterns" do
      enhancement = PathTraversalJoin.ast_enhancement()
      
      assert Enum.any?(enhancement.context_rules.exclude_paths, &(&1 == ~r/test/))
      assert Enum.any?(enhancement.context_rules.exclude_paths, &(&1 == ~r/build/))
      assert enhancement.context_rules.exclude_if_validated == true
      assert enhancement.context_rules.exclude_if_sandboxed == true
      assert enhancement.context_rules.exclude_if_allowlist_checked == true
      assert enhancement.context_rules.exclude_if_normalized_and_checked == true
      assert enhancement.context_rules.safe_path_functions == ["path.basename", "path.extname"]
    end
    
    test "confidence rules heavily penalize validation" do
      enhancement = PathTraversalJoin.ast_enhancement()
      
      assert enhancement.confidence_rules.base == 0.3
      assert enhancement.confidence_rules.adjustments["direct_user_path_to_join"] == 0.5
      assert enhancement.confidence_rules.adjustments["url_param_to_filesystem"] == 0.4
      assert enhancement.confidence_rules.adjustments["has_dot_dot_sequences"] == 0.3
      assert enhancement.confidence_rules.adjustments["uses_path_validation"] == -0.8
      assert enhancement.confidence_rules.adjustments["checks_resolved_path"] == -0.7
      assert enhancement.confidence_rules.adjustments["uses_basename_only"] == -0.9
      assert enhancement.confidence_rules.adjustments["static_base_path"] == -0.3
      assert enhancement.confidence_rules.adjustments["in_config_loader"] == -0.6
      assert enhancement.min_confidence == 0.8
    end
  end
  
  describe "enhanced_pattern/0" do
    test "returns pattern with AST enhancement from ast_enhancement/0" do
      enhanced = PathTraversalJoin.enhanced_pattern()
      enhancement = PathTraversalJoin.ast_enhancement()
      
      # Verify it has all the AST enhancement fields
      assert enhanced.ast_rules == enhancement.ast_rules
      assert enhanced.context_rules == enhancement.context_rules
      assert enhanced.confidence_rules == enhancement.confidence_rules
      assert enhanced.min_confidence == enhancement.min_confidence
      
      # And still has all the pattern fields
      assert enhanced.id == "js-path-traversal-join"
      assert enhanced.severity == :high
    end
  end
end