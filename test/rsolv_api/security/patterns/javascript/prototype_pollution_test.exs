defmodule RsolvApi.Security.Patterns.Javascript.PrototypePollutionTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Javascript.PrototypePollution
  alias RsolvApi.Security.Pattern
  
  doctest PrototypePollution
  
  # Test helpers for better readability
  defp get_pattern, do: PrototypePollution.pattern()
  
  defp assert_matches_code(pattern, code) do
    assert Regex.match?(pattern.regex, code), 
      "Pattern should match vulnerable code: #{code}"
  end
  
  defp refute_matches_code(pattern, code) do
    refute Regex.match?(pattern.regex, code),
      "Pattern should NOT match safe code: #{code}"
  end
  
  defp vulnerable_prototype_pollution_patterns do
    direct_property_assignment() ++
    object_assign_patterns() ++
    merge_utility_patterns() ++
    json_merge_patterns() ++
    config_override_patterns()
  end
  
  defp direct_property_assignment do
    [
      # Classic prototype pollution via bracket notation
      "obj[key] = value",
      "target[userKey] = userValue", 
      "config[req.body.key] = req.body.value",
      "settings[params.setting] = params.value",
      
      # Dynamic property assignment with user input
      "result[input.property] = input.data",
      "cache[query.id] = response.data",
      "store[body.name] = body.content",
      "registry[headers.type] = headers.value"
    ]
  end
  
  defp object_assign_patterns do
    [
      # Object.assign with user-controlled source objects
      "Object.assign(config, req.body)",
      "Object.assign(target, userInput)",
      "Object.assign(settings, request.data)",
      "Object.assign(options, req.params)",
      
      # Object.assign with multiple user sources  
      "Object.assign(config, req.body, req.query)",
      "Object.assign(target, input, defaults)",
      "Object.assign(state, payload.data)",
      "Object.assign(prototype, user.overrides)"
    ]
  end
  
  defp merge_utility_patterns do
    [
      # Common merge utilities vulnerable to prototype pollution  
      "_.merge(target, req.body)",
      "lodash.merge(config, userInput)",
      "jQuery.extend(target, userData)",
      "$.extend(target, input)"
    ]
  end
  
  defp json_merge_patterns do
    [
      # JSON-based merging that can cause prototype pollution
      "Object.assign(config, req.body)",
      "_.merge(settings, userInput)",
      "lodash.extend(target, payload)",
      "Object.assign(config, request.body)"
    ]
  end
  
  defp config_override_patterns do
    [
      # Configuration override patterns
      "for (let key in userConfig) { config[key] = userConfig[key] }",
      "Object.keys(input).forEach(k => target[k] = input[k])",
      "for (const prop in req.body) settings[prop] = req.body[prop]",
      "userKeys.forEach(key => obj[key] = userData[key])"
    ]
  end
  
  defp safe_prototype_pollution_patterns do
    validated_assignments() ++
    safe_merge_patterns() ++
    whitelist_approaches() ++
    safe_object_creation() ++
    non_object_operations()
  end
  
  defp validated_assignments do
    [
      # Safe assignment patterns - these shouldn't match our regex
      "obj.staticProperty = value",
      "target.property = value", 
      "config.setting = value",
      "this.property = value"
    ]
  end
  
  defp safe_merge_patterns do
    [
      # Safe object merging - patterns that don't match our regex
      "Object.assign({}, config)",
      "Object.assign(target)",
      "const result = merge(config)",
      "extend(target)"
    ]
  end
  
  defp whitelist_approaches do
    [
      # Safe patterns that don't trigger our regex
      "const safe = pick(req.body, allowedKeys)",
      "const filtered = Object.fromEntries(entries)",
      "config = { ...config, ...defaultSettings }",
      "settings = { name: input.name, email: input.email }"
    ]
  end
  
  defp safe_object_creation do
    [
      # Safe object creation that won't match our regex patterns
      "const safe = Object.create(null)",
      "const target = new Map()",
      "const settings = {}",
      "const empty = new Object()"
    ]
  end
  
  defp non_object_operations do
    [
      # Operations that aren't object property assignment
      "array.push(value)",
      "map.set(key, value)",
      "obj.method(key, value)",
      "const result = key + value",
      "if (obj.hasOwnProperty(key)) return obj[key]",
      "console.log(key, value)"
    ]
  end
  
  describe "PrototypePollution pattern" do
    test "returns correct pattern structure with all required fields" do
      pattern = get_pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-prototype-pollution"
      assert pattern.name == "Prototype Pollution"
      assert pattern.description == "Unsafe object property assignment can pollute object prototypes"
      assert pattern.type == :deserialization
      assert pattern.severity == :high
      assert pattern.languages == ["javascript", "typescript"]
      assert pattern.default_tier == :enterprise
      assert pattern.cwe_id == "CWE-1321"
      assert pattern.owasp_category == "A08:2021"
      assert is_binary(pattern.recommendation)
      assert is_map(pattern.test_cases)
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
    end
    
    test "detects all categories of prototype pollution vulnerabilities" do
      pattern = get_pattern()
      
      # Test each category of vulnerable patterns
      for code <- vulnerable_prototype_pollution_patterns() do
        assert_matches_code(pattern, code)
      end
    end
    
    test "correctly ignores safe object assignment patterns" do
      pattern = get_pattern()
      
      # Test each category of safe patterns
      for code <- safe_prototype_pollution_patterns() do
        refute_matches_code(pattern, code)
      end
    end
    
    test "provides comprehensive vulnerability metadata with proper structure" do
      metadata = PrototypePollution.vulnerability_metadata()
      
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
        assert PrototypePollution.applies_to_file?(file),
          "Should apply to JavaScript file: #{file}"
      end
      
      # Other language files should be rejected
      other_language_files = ["test.py", "app.rb", "server.php", "component.vue", "script.sh"]
      for file <- other_language_files do
        refute PrototypePollution.applies_to_file?(file),
          "Should NOT apply to non-JavaScript file: #{file}"
      end
    end
    
  end
  
  describe "ast_enhancement/0" do
    test "returns comprehensive AST enhancement rules" do
      enhancement = PrototypePollution.ast_enhancement()
      
      assert is_map(enhancement)
      assert Enum.sort(Map.keys(enhancement)) == Enum.sort([:ast_rules, :context_rules, :confidence_rules, :min_confidence])
    end
    
    test "AST rules target assignment expressions with computed members" do
      enhancement = PrototypePollution.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "AssignmentExpression"
      assert enhancement.ast_rules.left_side_analysis.is_computed_member_expression == true
      assert enhancement.ast_rules.left_side_analysis.has_prototype_chain_risk == true
      assert enhancement.ast_rules.left_side_analysis.uses_user_input_as_key == true
      
      # Check alternate patterns for Object.assign and merge functions
      assert is_list(enhancement.ast_rules.alternate_patterns)
      assert length(enhancement.ast_rules.alternate_patterns) > 0
    end
    
    test "context rules exclude test files and validated keys" do
      enhancement = PrototypePollution.ast_enhancement()
      
      assert Enum.any?(enhancement.context_rules.exclude_paths, &(&1 == ~r/test/))
      assert Enum.any?(enhancement.context_rules.exclude_paths, &(&1 == ~r/spec/))
      assert enhancement.context_rules.exclude_if_prototype_frozen == true
      assert enhancement.context_rules.exclude_if_key_validated == true
      assert enhancement.context_rules.exclude_if_using_map == true
      assert enhancement.context_rules.exclude_if_schema_validated == true
      assert enhancement.context_rules.dangerous_keys == ["__proto__", "constructor", "prototype"]
    end
    
    test "confidence rules heavily penalize validated and safe patterns" do
      enhancement = PrototypePollution.ast_enhancement()
      
      assert enhancement.confidence_rules.base == 0.3
      assert enhancement.confidence_rules.adjustments["direct_proto_assignment"] == 0.6
      assert enhancement.confidence_rules.adjustments["user_key_in_bracket_notation"] == 0.4
      assert enhancement.confidence_rules.adjustments["object_merge_with_user_data"] == 0.3
      assert enhancement.confidence_rules.adjustments["validates_against_proto"] == -0.9
      assert enhancement.confidence_rules.adjustments["uses_object_create_null"] == -0.8
      assert enhancement.confidence_rules.adjustments["has_schema_validation"] == -0.7
      assert enhancement.confidence_rules.adjustments["uses_map_not_object"] == -1.0
      assert enhancement.min_confidence == 0.7
    end
  end
  
  describe "enhanced_pattern/0" do
    test "returns pattern with AST enhancement from ast_enhancement/0" do
      enhanced = PrototypePollution.enhanced_pattern()
      enhancement = PrototypePollution.ast_enhancement()
      
      # Verify it has all the AST enhancement fields
      assert enhanced.ast_rules == enhancement.ast_rules
      assert enhanced.context_rules == enhancement.context_rules
      assert enhanced.confidence_rules == enhancement.confidence_rules
      assert enhanced.min_confidence == enhancement.min_confidence
      
      # And still has all the pattern fields
      assert enhanced.id == "js-prototype-pollution"
      assert enhanced.severity == :high
    end
  end
end