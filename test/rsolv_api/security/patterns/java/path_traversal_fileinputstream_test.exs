defmodule RsolvApi.Security.Patterns.Java.PathTraversalFileinputstreamTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Java.PathTraversalFileinputstream
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = PathTraversalFileinputstream.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "java-path-traversal-fileinputstream"
      assert pattern.name == "Path Traversal via FileInputStream"
      assert pattern.severity == :high
      assert pattern.type == :path_traversal
      assert pattern.languages == ["java"]
      assert pattern.cwe_id == "CWE-22"
      assert pattern.owasp_category == "A01:2021"
      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 4
      assert Enum.all?(pattern.regex, &is_struct(&1, Regex))
    end
    
    test "includes comprehensive test cases" do
      pattern = PathTraversalFileinputstream.pattern()
      
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
      assert is_list(pattern.test_cases.vulnerable)
      assert is_list(pattern.test_cases.safe)
      assert length(pattern.test_cases.vulnerable) >= 2
      assert length(pattern.test_cases.safe) >= 2
    end
    
    test "has appropriate recommendation" do
      pattern = PathTraversalFileinputstream.pattern()
      
      assert String.contains?(String.downcase(pattern.recommendation), "validate")
      assert String.contains?(String.downcase(pattern.recommendation), "fileinputstream") or
             String.contains?(String.downcase(pattern.recommendation), "files.newinputstream")
    end
  end
  
  describe "regex matching" do
    test "detects FileInputStream constructor with string concatenation" do
      pattern = PathTraversalFileinputstream.pattern()
      
      vulnerable_code = [
        "FileInputStream fis = new FileInputStream(baseDir + filename);",
        "new FileInputStream(\"/uploads/\" + userFile);",
        "FileInputStream stream = new FileInputStream(directory + File.separator + fileName);",
        "FileInputStream in = new FileInputStream(rootPath + \"/\" + request.getParameter(\"file\"));",
        "FileInputStream reader = new FileInputStream(uploadPath + userInput);",
        "new FileInputStream(System.getProperty(\"user.home\") + \"/\" + filename);",
        "FileInputStream file = new FileInputStream(basePath + File.separator + relativePath);"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects FileInputStream with variable concatenation" do
      pattern = PathTraversalFileinputstream.pattern()
      
      vulnerable_code = [
        "String fullPath = baseDir + filename;\nFileInputStream fis = new FileInputStream(fullPath);",
        "String path = \"/var/uploads/\" + userDir;\nnew FileInputStream(path);",
        "String fileName = request.getParameter(\"file\");\nFileInputStream f = new FileInputStream(uploadDir + fileName);"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects FileInputStream with method call concatenation" do
      pattern = PathTraversalFileinputstream.pattern()
      
      vulnerable_code = [
        "new FileInputStream(config.getUploadPath() + \"/\" + request.getFile());",
        "FileInputStream download = new FileInputStream(DOWNLOAD_DIR + File.separator + fileName);",
        "return new FileInputStream(getServletContext().getRealPath(\"/\") + userPath);",
        "FileInputStream is = new FileInputStream(Paths.get(base).toString() + \"/\" + file);"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe FileInputStream usage" do
      pattern = PathTraversalFileinputstream.pattern()
      
      safe_code = [
        "FileInputStream fis = new FileInputStream(\"config.properties\");",
        "new FileInputStream(\"/etc/app/settings.conf\");",
        "FileInputStream temp = new FileInputStream(tempFile);",
        "// Comment about FileInputStream paths\n// FileInputStream fis = new FileInputStream(base + user);",
        "Path path = Paths.get(uploadDir, filename).normalize();\nif (path.startsWith(uploadDir)) {\n    FileInputStream fis = new FileInputStream(path.toFile());\n}",
        "String safeFilename = Paths.get(filename).getFileName().toString();\nFileInputStream fis = new FileInputStream(new File(uploadDir, safeFilename));",
        "FileInputStream fis = new FileInputStream(validatedFile);"
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should not match: #{code}"
      end
    end
    
    test "detects try-with-resources FileInputStream patterns" do
      pattern = PathTraversalFileinputstream.pattern()
      
      vulnerable_code = [
        "try (FileInputStream fis = new FileInputStream(baseDir + userFile)) {",
        "try (FileInputStream stream = new FileInputStream(\"/data/\" + fileName)) {",
        "try (FileInputStream in = new FileInputStream(directory + File.separator + file)) {"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = PathTraversalFileinputstream.vulnerability_metadata()
      
      assert String.contains?(String.downcase(metadata.description), "path traversal")
      assert String.contains?(metadata.description, "FileInputStream")
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 5
      assert length(metadata.real_world_impact) >= 4
      assert length(metadata.cve_examples) >= 2
    end
    
    test "includes Java FileInputStream-specific information" do
      metadata = PathTraversalFileinputstream.vulnerability_metadata()
      
      assert String.contains?(metadata.description, "FileInputStream")
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "Files.newInputStream"))
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "Path"))
    end
    
    test "includes proper security references" do
      metadata = PathTraversalFileinputstream.vulnerability_metadata()
      
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
    
    test "includes path traversal attack vectors" do
      metadata = PathTraversalFileinputstream.vulnerability_metadata()
      
      assert Enum.any?(metadata.attack_vectors, &String.contains?(&1, "../"))
      assert Enum.any?(metadata.attack_vectors, &String.contains?(&1, "..\\"))
    end
    
    test "includes CVE examples with proper structure" do
      metadata = PathTraversalFileinputstream.vulnerability_metadata()
      
      for cve <- metadata.cve_examples do
        assert Map.has_key?(cve, :id)
        assert Map.has_key?(cve, :description)
        assert Map.has_key?(cve, :severity)
        assert Map.has_key?(cve, :cvss)
        assert is_number(cve.cvss)
        assert cve.cvss > 0
      end
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = PathTraversalFileinputstream.ast_enhancement()
      
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.7
    end
    
    test "includes FileInputStream constructor analysis" do
      enhancement = PathTraversalFileinputstream.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "NewExpression"
      assert enhancement.ast_rules.fileinputstream_analysis.check_constructor_name
      assert enhancement.ast_rules.fileinputstream_analysis.constructor_patterns
      assert enhancement.ast_rules.fileinputstream_analysis.check_argument_concatenation
    end
    
    test "has path concatenation detection" do
      enhancement = PathTraversalFileinputstream.ast_enhancement()
      
      assert enhancement.ast_rules.concatenation_analysis.check_operators
      assert enhancement.ast_rules.concatenation_analysis.dangerous_operators
      assert enhancement.ast_rules.concatenation_analysis.check_method_calls
    end
    
    test "includes safe pattern detection" do
      enhancement = PathTraversalFileinputstream.ast_enhancement()
      
      assert enhancement.context_rules.check_path_validation
      assert enhancement.context_rules.safe_patterns
      assert enhancement.context_rules.validation_methods
    end
    
    test "has proper confidence scoring" do
      enhancement = PathTraversalFileinputstream.ast_enhancement()
      
      adjustments = enhancement.confidence_rules.adjustments
      assert Map.has_key?(adjustments, "has_string_concatenation")
      assert Map.has_key?(adjustments, "has_user_input_method")
      assert Map.has_key?(adjustments, "has_path_validation")
      assert Map.has_key?(adjustments, "is_constant_path")
    end
  end
end