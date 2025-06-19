defmodule RsolvApi.Security.Patterns.Java.PathTraversalFileTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Java.PathTraversalFile
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = PathTraversalFile.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "java-path-traversal-file"
      assert pattern.name == "Path Traversal via File"
      assert pattern.severity == :high
      assert pattern.type == :path_traversal
      assert pattern.languages == ["java"]
      assert pattern.cwe_id == "CWE-22"
      assert pattern.owasp_category == "A01:2021"
      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 6
      assert Enum.all?(pattern.regex, &is_struct(&1, Regex))
      assert pattern.default_tier == :ai
    end
    
    test "includes comprehensive test cases" do
      pattern = PathTraversalFile.pattern()
      
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
      assert is_list(pattern.test_cases.vulnerable)
      assert is_list(pattern.test_cases.safe)
      assert length(pattern.test_cases.vulnerable) >= 2
      assert length(pattern.test_cases.safe) >= 2
    end
    
    test "has appropriate recommendation" do
      pattern = PathTraversalFile.pattern()
      
      assert String.contains?(String.downcase(pattern.recommendation), "validate")
      assert String.contains?(String.downcase(pattern.recommendation), "sanitize") or 
             String.contains?(String.downcase(pattern.recommendation), "canonical")
    end
  end
  
  describe "regex matching" do
    test "detects File constructor with string concatenation" do
      pattern = PathTraversalFile.pattern()
      
      vulnerable_code = [
        "File file = new File(uploadDir + \"/\" + filename);",
        "new File(baseDir + File.separator + userPath);",
        "File f = new File(\"/uploads/\" + userInput);",
        "File output = new File(directory + fileName);",
        "new File(rootPath + \"/\" + request.getParameter(\"file\"));",
        "File resource = new File(basePath + File.separator + relativePath);",
        "file = new File(System.getProperty(\"user.home\") + \"/\" + filename);"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects File constructor with variable concatenation" do
      pattern = PathTraversalFile.pattern()
      
      vulnerable_code = [
        "String fullPath = baseDir + filename;\nFile file = new File(fullPath);",
        "String path = \"/var/uploads/\" + userDir;\nnew File(path);",
        "String fileName = request.getParameter(\"file\");\nFile f = new File(uploadDir + fileName);"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe File usage" do
      pattern = PathTraversalFile.pattern()
      
      safe_code = [
        "File file = new File(\"config.properties\");",
        "new File(\"/etc/app/settings.conf\");",
        "File temp = File.createTempFile(\"upload\", \".tmp\");",
        "// Comment about File paths\n// File file = new File(base + user);",
        "Path path = Paths.get(uploadDir, filename).normalize();\nif (path.startsWith(uploadDir)) {\n    File file = path.toFile();\n}",
        "String safeFilename = Paths.get(filename).getFileName().toString();\nFile file = new File(uploadDir, safeFilename);"
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should not match: #{code}"
      end
    end
    
    test "matches complex concatenation patterns" do
      pattern = PathTraversalFile.pattern()
      
      vulnerable_code = [
        "new File(config.getUploadPath() + \"/\" + request.getFile());",
        "File download = new File(DOWNLOAD_DIR + File.separator + fileName);",
        "return new File(getServletContext().getRealPath(\"/\") + userPath);"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = PathTraversalFile.vulnerability_metadata()
      
      assert String.contains?(String.downcase(metadata.description), "path traversal")
      assert String.contains?(metadata.description, "File constructor")
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 5
      assert length(metadata.real_world_impact) >= 4
      assert length(metadata.cve_examples) >= 2
    end
    
    test "includes Java-specific information" do
      metadata = PathTraversalFile.vulnerability_metadata()
      
      assert String.contains?(metadata.description, "File")
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "Paths.get"))
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "canonical"))
    end
    
    test "includes proper security references" do
      metadata = PathTraversalFile.vulnerability_metadata()
      
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
    
    test "includes path traversal attack vectors" do
      metadata = PathTraversalFile.vulnerability_metadata()
      
      assert Enum.any?(metadata.attack_vectors, &String.contains?(&1, "../"))
      assert Enum.any?(metadata.attack_vectors, &String.contains?(&1, "..\\"))
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = PathTraversalFile.ast_enhancement()
      
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.7
    end
    
    test "includes File constructor analysis" do
      enhancement = PathTraversalFile.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "NewExpression"
      assert enhancement.ast_rules.file_analysis.check_constructor_name
      assert enhancement.ast_rules.file_analysis.constructor_patterns
      assert enhancement.ast_rules.file_analysis.check_argument_concatenation
    end
    
    test "has path concatenation detection" do
      enhancement = PathTraversalFile.ast_enhancement()
      
      assert enhancement.ast_rules.concatenation_analysis.check_operators
      assert enhancement.ast_rules.concatenation_analysis.dangerous_operators
      assert enhancement.ast_rules.concatenation_analysis.check_method_calls
    end
    
    test "includes safe pattern detection" do
      enhancement = PathTraversalFile.ast_enhancement()
      
      assert enhancement.context_rules.check_path_validation
      assert enhancement.context_rules.safe_patterns
      assert enhancement.context_rules.validation_methods
    end
  end
end