defmodule RsolvApi.Security.Patterns.Javascript.InsecureDeserializationTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Javascript.InsecureDeserialization
  alias RsolvApi.Security.Pattern
  
  # Test helpers for better readability
  defp get_pattern, do: InsecureDeserialization.pattern()
  
  defp assert_matches_code(pattern, code) do
    assert Regex.match?(pattern.regex, code), 
      "Pattern should match vulnerable code: #{code}"
  end
  
  defp refute_matches_code(pattern, code) do
    refute Regex.match?(pattern.regex, code),
      "Pattern should NOT match safe code: #{code}"
  end
  
  @doc """
  Returns all categories of vulnerable deserialization patterns for testing.
  """
  defp vulnerable_deserialization_patterns do
    json_parse_patterns() ++
    yaml_load_patterns() ++
    custom_deserialize_patterns() ++
    xml_parse_patterns() ++
    eval_based_patterns()
  end
  
  defp json_parse_patterns do
    [
      # Direct JSON.parse with user input
      "JSON.parse(req.body.data)",
      "JSON.parse(request.body)",
      "JSON.parse(params.config)",
      "JSON.parse(query.settings)",
      
      # JSON.parse with user-controlled sources
      "const config = JSON.parse(userInput)",
      "settings = JSON.parse(input)",
      "var obj = JSON.parse(data)",
      "return JSON.parse(payload)"
    ]
  end
  
  defp yaml_load_patterns do
    [
      # YAML parsing with user input (dangerous in JS)
      "yaml.load(req.body.config)",
      "YAML.load(userInput)",
      "yamljs.load(params.data)",
      "js-yaml.load(input)",
      
      # YAML with various user sources
      "yaml.load(request.body.template)",
      "YAML.parse(query.manifest)",
      "yamlParser.load(payload)",
      "loadYaml(userData)"
    ]
  end
  
  defp custom_deserialize_patterns do
    [
      # Custom deserialization functions with user input
      "deserialize(req.body)",
      "unserialize(userInput)",
      "fromJSON(params.data)",
      "parseObject(input)",
      
      # Various deserialization patterns
      "deserialize(request.body)",
      "unserialize(query.obj)",
      "deserialize(payload)",
      "reconstruct(userData)"
    ]
  end
  
  defp xml_parse_patterns do
    [
      # XML parsing that could be exploited
      "xmlParse(req.body.xml)",
      "parseXML(userInput)",
      "xml2js.parseString(data)",
      "xmlParser.parse(input)",
      
      # Various XML parsing patterns
      "parseXmlString(request.body)",
      "xmlToObject(params.doc)",
      "convertXML(query.data)",
      "processXML(payload)"
    ]
  end
  
  defp eval_based_patterns do
    [
      # Eval-like deserialization (very dangerous)
      "eval(req.body)",
      "Function('return ' + userInput)()",
      "new Function('return ' + data)()",
      "eval(input)",
      
      # VM-based execution
      "vm.runInContext(req.body)",
      "runInNewContext(userInput)",
      "new vm.Script(data)"
    ]
  end
  
  @doc """
  Returns all categories of safe deserialization patterns that should not match.
  These represent secure coding practices that prevent deserialization attacks.
  """
  defp safe_deserialization_patterns do
    validated_parsing() ++
    safe_yaml_patterns() ++
    schema_validation() ++
    sanitized_input() ++
    non_deserialization_operations()
  end
  
  defp validated_parsing do
    [
      # Parsing with validation - these are tricky because the regex might still catch them
      "const validated = validateInput(req.body); JSON.parse(validated)",
      "const obj = safeParse(userInput)",
      "parseSecurely(req.body)",
      "safeDeserialize(data)"
    ]
  end
  
  defp safe_yaml_patterns do
    [
      # Safe YAML loading
      "yaml.safeLoad(req.body.config)",
      "YAML.safeLoad(userInput)",
      "yamljs.safeLoad(data)",
      "js-yaml.safeLoad(input)"
    ]
  end
  
  defp schema_validation do
    [
      # Schema-based validation before parsing
      "if (isValidJSON(staticConfig)) { JSON.parse(staticConfig) }",
      "const validated = ajv.validate(schema, safeConfig) ? JSON.parse(safeConfig) : null",
      "parseWithSchema(hardcodedConfig, userSchema)",
      "strictParse(constantValue, expectedFormat)"
    ]
  end
  
  defp sanitized_input do
    [
      # Pre-sanitized or filtered input
      "JSON.parse(escapeHtml(staticString))",
      "JSON.parse(configString)",
      "JSON.parse(hardcodedConfig)",
      "JSON.parse(cleanString)"
    ]
  end
  
  defp non_deserialization_operations do
    [
      # Operations that don't involve deserialization
      "JSON.stringify(obj)",
      "const str = data.toString()",
      "console.log(JSON.parse(hardcodedString))",
      "return { data: sanitizedData }"
    ]
  end
  
  describe "InsecureDeserialization pattern" do
    test "returns correct pattern structure with all required fields" do
      pattern = get_pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-insecure-deserialization"
      assert pattern.name == "Insecure Deserialization"
      assert pattern.description == "Deserializing untrusted data can lead to remote code execution"
      assert pattern.type == :deserialization
      assert pattern.severity == :high
      assert pattern.languages == ["javascript", "typescript"]
      assert pattern.default_tier == :protected
      assert pattern.cwe_id == "CWE-502"
      assert pattern.owasp_category == "A08:2021"
      assert is_binary(pattern.recommendation)
      assert is_map(pattern.test_cases)
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
    end
    
    test "detects all categories of insecure deserialization vulnerabilities" do
      pattern = get_pattern()
      
      # Test each category of vulnerable patterns
      for code <- vulnerable_deserialization_patterns() do
        assert_matches_code(pattern, code)
      end
    end
    
    test "correctly ignores safe deserialization patterns" do
      pattern = get_pattern()
      
      # Test each category of safe patterns
      for code <- safe_deserialization_patterns() do
        refute_matches_code(pattern, code)
      end
    end
    
    test "provides comprehensive vulnerability metadata with proper structure" do
      metadata = InsecureDeserialization.vulnerability_metadata()
      
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
    
    test "correctly identifies applicable file types for JavaScript and TypeScript" do
      # JavaScript and TypeScript files should be detected
      javascript_files = ["test.js", "app.jsx", "server.ts", "component.tsx", "module.mjs"]
      for file <- javascript_files do
        assert InsecureDeserialization.applies_to_file?(file),
          "Should apply to JavaScript file: #{file}"
      end
      
      # Other language files should be rejected
      other_language_files = ["test.py", "app.rb", "server.php", "component.vue", "script.sh"]
      for file <- other_language_files do
        refute InsecureDeserialization.applies_to_file?(file),
          "Should NOT apply to non-JavaScript file: #{file}"
      end
    end
    
    test "ast_enhancement/0 returns correct structure" do
      enhancement = InsecureDeserialization.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      # Check AST rules
      assert is_map(enhancement.ast_rules)
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert is_map(enhancement.ast_rules.callee_patterns)
      
      # Check context rules
      assert is_map(enhancement.context_rules)
      assert is_list(enhancement.context_rules.exclude_paths)
      assert is_list(enhancement.context_rules.safe_patterns)
      
      # Check confidence rules
      assert is_map(enhancement.confidence_rules)
      assert is_number(enhancement.confidence_rules.base)
      assert is_map(enhancement.confidence_rules.adjustments)
      
      # Check min confidence
      assert is_number(enhancement.min_confidence)
      assert enhancement.min_confidence >= 0.0
      assert enhancement.min_confidence <= 1.0
    end
    
    test "AST rules specify deserialization function patterns" do
      enhancement = InsecureDeserialization.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert is_map(enhancement.ast_rules.callee_patterns)
      assert is_list(enhancement.ast_rules.callee_patterns.json_parsers)
      assert "JSON.parse" in enhancement.ast_rules.callee_patterns.json_parsers
    end
    
    test "context rules exclude test files and check for safe patterns" do
      enhancement = InsecureDeserialization.ast_enhancement()
      
      # Should exclude test directories
      exclude_paths = enhancement.context_rules.exclude_paths
      assert Enum.any?(exclude_paths, &Regex.match?(&1, "test/"))
      assert Enum.any?(exclude_paths, &Regex.match?(&1, "fixtures/"))
      
      # Should have safe patterns
      assert is_list(enhancement.context_rules.safe_patterns)
      assert "yaml.safeLoad" in enhancement.context_rules.safe_patterns
      assert "ajv.validate" in enhancement.context_rules.safe_patterns
    end
    
    test "confidence scoring adjusts for deserialization context" do
      enhancement = InsecureDeserialization.ast_enhancement()
      
      adjustments = enhancement.confidence_rules.adjustments
      
      # Should have positive adjustments for dangerous patterns
      assert adjustments["yaml_load"] > 0
      assert adjustments["eval_deserialization"] > 0
      assert adjustments["user_input"] > 0
      
      # Should have negative adjustments for safe patterns
      assert adjustments["safe_yaml"] < 0
      assert adjustments["schema_validation"] < 0
      assert adjustments["hardcoded_input"] < 0
    end
    
  end
end