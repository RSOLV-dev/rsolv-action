defmodule RsolvApi.Security.Patterns.Javascript.XxeExternalEntitiesTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Javascript.XxeExternalEntities
  alias RsolvApi.Security.Pattern
  
  # Test helpers
  defp get_pattern, do: XxeExternalEntities.pattern()
  
  defp assert_matches_code(pattern, code) do
    assert Regex.match?(pattern.regex, code), 
      "Pattern should match vulnerable code: #{code}"
  end
  
  defp refute_matches_code(pattern, code) do
    refute Regex.match?(pattern.regex, code),
      "Pattern should NOT match safe code: #{code}"
  end
  
  describe "XxeExternalEntities pattern structure" do
    test "returns correct pattern structure with all required fields" do
      pattern = get_pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-xxe-external-entities"
      assert pattern.name == "XML External Entity (XXE) Injection"
      assert pattern.description == "XML parsers with external entities enabled can read files and perform SSRF"
      assert pattern.type == :xxe
      assert pattern.severity == :high
      assert pattern.languages == ["javascript", "typescript"]
      assert pattern.default_tier == :protected
      assert pattern.cwe_id == "CWE-611"
      assert pattern.owasp_category == "A05:2021"
      assert is_binary(pattern.recommendation)
      assert is_map(pattern.test_cases)
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
    end
  end

  describe "vulnerability detection" do
    test "detects DOMParser instantiation" do
      pattern = get_pattern()
      
      vulnerable_patterns = [
        "parser = new DOMParser()",
        "const parser = new DOMParser()",
        "let xmlParser = new DOMParser()",
        "var parser = new window.DOMParser()",
        "this.parser = new DOMParser()"
      ]
      
      for code <- vulnerable_patterns do
        assert_matches_code(pattern, code)
      end
    end

    test "detects XML parsing methods" do
      pattern = get_pattern()
      
      vulnerable_patterns = [
        "parser.parseFromString(xmlData, 'text/xml')",
        "parser.parseFromString(userXml, \"application/xml\")",
        "doc = parser.parseFromString(xmlContent, 'text/xml')",
        "const xmlDoc = parser.parseFromString(xmlString, \"text/xml\")"
      ]
      
      for code <- vulnerable_patterns do
        assert_matches_code(pattern, code)
      end
    end

    test "detects jQuery parseXML" do
      pattern = get_pattern()
      
      vulnerable_patterns = [
        "$.parseXML(xmlString)",
        "jQuery.parseXML(userXml)",
        "const doc = $.parseXML(xmlData)",
        "xmlDoc = jQuery.parseXML(xmlContent)"
      ]
      
      for code <- vulnerable_patterns do
        assert_matches_code(pattern, code)
      end
    end

    test "detects other XML parsing libraries" do
      pattern = get_pattern()
      
      vulnerable_patterns = [
        "xmldom.DOMParser()",
        "new XMLParser()",
        "xml2js.parseString(xmlData)",
        "libxmljs.parseXml(xmlString)",
        "new fast-xml-parser.XMLParser()"
      ]
      
      for code <- vulnerable_patterns do
        assert_matches_code(pattern, code)
      end
    end
  end

  describe "safe pattern recognition" do
    test "ignores JSON parsing" do
      pattern = get_pattern()
      
      safe_patterns = [
        "JSON.parse(jsonData)",
        "const data = JSON.parse(response)",
        "JSON.stringify(object)",
        "JSON.parse(sanitizedData)"
      ]
      
      for code <- safe_patterns do
        refute_matches_code(pattern, code)
      end
    end

    test "ignores safe XML configurations" do
      pattern = get_pattern()
      
      safe_patterns = [
        "// Use JSON instead of XML",
        "const safeParser = createSafeXmlParser()",
        "parser.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true)",
        "xmlDoc = sanitizeAndParseXml(data)"
      ]
      
      for code <- safe_patterns do
        refute_matches_code(pattern, code)
      end
    end

    test "ignores unrelated parsing" do
      pattern = get_pattern()
      
      safe_patterns = [
        "const parser = new URLSearchParams()",
        "markdown.parse(text)",
        "html.parseFragment(htmlString)",
        "yaml.parse(yamlData)"
      ]
      
      for code <- safe_patterns do
        refute_matches_code(pattern, code)
      end
    end
  end

  describe "vulnerability metadata" do
    test "provides comprehensive vulnerability metadata with proper structure" do
      metadata = XxeExternalEntities.vulnerability_metadata()
      
      # Basic structure validation
      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert String.length(metadata.description) > 100
      
      # Validate authoritative references
      assert is_list(metadata.references)
      assert length(metadata.references) >= 4
      
      valid_reference_types = [:cwe, :owasp, :nist, :research, :sans, :vendor]
      for ref <- metadata.references do
        assert Map.has_key?(ref, :type)
        assert Map.has_key?(ref, :url)
        assert ref.type in valid_reference_types
        assert String.starts_with?(ref.url, "http")
      end
      
      # Validate attack methodology documentation
      assert is_list(metadata.attack_vectors) and length(metadata.attack_vectors) >= 5
      assert is_list(metadata.real_world_impact) and length(metadata.real_world_impact) >= 5
      assert is_list(metadata.safe_alternatives) and length(metadata.safe_alternatives) >= 5
      
      # Validate CVE examples with proper severity classification
      assert is_list(metadata.cve_examples)
      assert length(metadata.cve_examples) >= 3
      
      valid_severities = ["low", "medium", "high", "critical"]
      for cve <- metadata.cve_examples do
        assert Map.has_key?(cve, :id)
        assert Map.has_key?(cve, :description)
        assert Map.has_key?(cve, :severity)
        assert String.starts_with?(cve.id, "CVE-")
        assert cve.severity in valid_severities
      end
      
      # Validate detection methodology documentation
      assert is_binary(metadata.detection_notes)
      assert String.length(metadata.detection_notes) > 50
    end
  end

  describe "file type detection" do
    test "applies to JavaScript and TypeScript files" do
      javascript_files = ["test.js", "app.jsx", "server.ts", "component.tsx", "module.mjs"]
      
      for file <- javascript_files do
        assert XxeExternalEntities.applies_to_file?(file),
          "Should apply to JavaScript file: #{file}"
      end
    end

    test "does not apply to other language files" do
      other_language_files = ["test.py", "app.rb", "server.php", "component.vue", "script.sh"]
      
      for file <- other_language_files do
        refute XxeExternalEntities.applies_to_file?(file),
          "Should NOT apply to non-JavaScript file: #{file}"
      end
    end
  end
  
  describe "AST enhancement" do
    test "ast_enhancement/0 returns correct structure" do
      enhancement = XxeExternalEntities.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      # Check AST rules
      assert is_map(enhancement.ast_rules)
      assert enhancement.ast_rules.node_type == "NewExpression"
      assert is_list(enhancement.ast_rules.parser_names)
      
      # Check context rules
      assert is_map(enhancement.context_rules)
      assert is_list(enhancement.context_rules.exclude_paths)
      assert is_list(enhancement.context_rules.safe_configurations)
      
      # Check confidence rules
      assert is_map(enhancement.confidence_rules)
      assert is_number(enhancement.confidence_rules.base)
      assert is_map(enhancement.confidence_rules.adjustments)
      
      # Check min confidence
      assert is_number(enhancement.min_confidence)
      assert enhancement.min_confidence >= 0.0
      assert enhancement.min_confidence <= 1.0
    end
    
    test "AST rules specify XML parser patterns" do
      enhancement = XxeExternalEntities.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "NewExpression"
      assert is_list(enhancement.ast_rules.parser_names)
      assert "DOMParser" in enhancement.ast_rules.parser_names
      assert "XMLParser" in enhancement.ast_rules.parser_names
    end
    
    test "context rules exclude test files and check for safe configurations" do
      enhancement = XxeExternalEntities.ast_enhancement()
      
      # Should exclude test directories
      exclude_paths = enhancement.context_rules.exclude_paths
      assert Enum.any?(exclude_paths, &Regex.match?(&1, "test/"))
      assert Enum.any?(exclude_paths, &Regex.match?(&1, "mocks/"))
      
      # Should have safe configurations
      assert is_list(enhancement.context_rules.safe_configurations)
      assert "noent: false" in enhancement.context_rules.safe_configurations
      assert "expandEntities: false" in enhancement.context_rules.safe_configurations
    end
    
    test "confidence scoring adjusts for XML parsing context" do
      enhancement = XxeExternalEntities.ast_enhancement()
      
      adjustments = enhancement.confidence_rules.adjustments
      
      # Should have positive adjustments for dangerous patterns
      assert adjustments["node_xml_parser"] > 0
      assert adjustments["external_entity_enabled"] > 0
      assert adjustments["user_controlled_xml"] > 0
      
      # Should have negative adjustments for safe patterns
      assert adjustments["browser_domparser"] < 0
      assert adjustments["safe_configuration"] < 0
      assert adjustments["json_alternative"] < 0
    end
  end
end