defmodule RsolvApi.Security.Patterns.Javascript.UnsafeRegexTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Javascript.UnsafeRegex
  alias RsolvApi.Security.Pattern
  
  # Test helpers for better readability
  defp get_pattern, do: UnsafeRegex.pattern()
  
  defp assert_matches_code(pattern, code) do
    assert Regex.match?(pattern.regex, code), 
      "Pattern should match vulnerable code: #{code}"
  end
  
  defp refute_matches_code(pattern, code) do
    refute Regex.match?(pattern.regex, code),
      "Pattern should NOT match safe code: #{code}"
  end
  
  defp vulnerable_regex_patterns do
    nested_plus_quantifiers() ++ 
    nested_star_quantifiers() ++ 
    curly_brace_quantifiers() ++ 
    alternation_overlap_patterns() ++ 
    real_world_redos_patterns()
  end
  
  defp nested_plus_quantifiers do
    [
      # Classic nested plus quantifiers that cause exponential backtracking
      "new RegExp(\"(a+)+$\")",
      "/(x+x+)+y/.test(input)",
      "/^(a+)+$/.test(userInput)",
      "/(a+)+(b+)+c/.test(data)"
    ]
  end
  
  defp nested_star_quantifiers do
    [
      # Nested star quantifiers with similar exponential behavior
      "const pattern = /(a*)*b/",
      "/(.*)*$/.test(input)",
      "/([a-zA-Z]+)*/.test(input)",
      "/(\\w*)*@.*\\..*/.test(email)"
    ]
  end
  
  defp curly_brace_quantifiers do
    [
      # Curly brace quantifiers combined with other quantifiers
      "new RegExp(\"(.*a){20}\")",
      "new RegExp(\"(\\\\d+)*\\\\d\")"
    ]
  end
  
  defp alternation_overlap_patterns do
    [
      # Overlapping alternation patterns that cause ReDoS
      "/(a|a)*/.test(text)",
      "pattern = /(a|a)*b/",
      "new RegExp(\"(a*|a*)*)\")"
    ]
  end
  
  defp real_world_redos_patterns do
    [
      # Email and other validation patterns prone to ReDoS
      "/([a-zA-Z0-9_\\.-]+)+@/",
      "new RegExp(\"(\\\\w+)+@(\\\\w+)+\\\\.\")"
    ]
  end
  
  defp safe_regex_patterns do
    simple_quantifiers() ++ 
    bounded_quantifiers() ++ 
    non_overlapping_alternations() ++ 
    character_classes() ++ 
    non_regex_operations()
  end
  
  defp simple_quantifiers do
    [
      # Simple quantifiers without dangerous nesting
      "new RegExp(\"a+$\")",
      "/x+y/.test(input)",
      "const pattern = /a*b/",
      "/a++b/.test(input)"  # Possessive quantifier (conceptual)
    ]
  end
  
  defp bounded_quantifiers do
    [
      # Quantifiers with explicit bounds that prevent exponential behavior
      "new RegExp(\"\\\\d{1,10}\")",
      "/a{1,5}/.test(input)",
      "new RegExp(\"\\\\w{3,20}\")",
      "/[0-9]{1,3}/.test(number)"
    ]
  end
  
  defp non_overlapping_alternations do
    [
      # Alternations without overlap - safe from ReDoS
      "/(cat|dog)/.test(animal)",
      "new RegExp(\"(yes|no)\")",
      "/\\d+|\\w+/.test(input)"
    ]
  end
  
  defp character_classes do
    [
      # Character classes and simple patterns
      "/[a-z]+/.test(text)",
      "/[a-zA-Z]+/.test(input)",
      "new RegExp(\"\\\\d+\")",
      "/\\w+@\\w+\\.\\w+/.test(email)"
    ]
  end
  
  defp non_regex_operations do
    [
      # String operations that aren't regex at all
      "input.replace(\"pattern\", \"replacement\")",
      "text.match(\"simple\")",
      "const result = \"test\".includes(pattern)"
    ]
  end
  
  describe "UnsafeRegex pattern" do
    test "returns correct pattern structure with all required fields" do
      pattern = get_pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-unsafe-regex"
      assert pattern.name == "Regular Expression Denial of Service (ReDoS)"
      assert pattern.description == "Regex with nested quantifiers can cause exponential backtracking"
      assert pattern.type == :denial_of_service
      assert pattern.severity == :medium
      assert pattern.languages == ["javascript", "typescript"]
      assert pattern.default_tier == :ai
      assert pattern.cwe_id == "CWE-1333"
      assert pattern.owasp_category == "A05:2021"
      assert is_binary(pattern.recommendation)
      assert is_map(pattern.test_cases)
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
    end
    
    test "detects nested quantifier patterns that cause ReDoS vulnerabilities" do
      pattern = get_pattern()
      
      # Test each category of vulnerable patterns
      for code <- vulnerable_regex_patterns() do
        assert_matches_code(pattern, code)
      end
    end
    
    test "correctly ignores safe regex patterns without ReDoS vulnerabilities" do
      pattern = get_pattern()
      
      # Test each category of safe patterns
      for code <- safe_regex_patterns() do
        refute_matches_code(pattern, code)
      end
    end
    
    test "provides comprehensive vulnerability metadata with proper structure" do
      metadata = UnsafeRegex.vulnerability_metadata()
      
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
        assert UnsafeRegex.applies_to_file?(file),
          "Should apply to JavaScript file: #{file}"
      end
      
      # Other language files should be rejected
      other_language_files = ["test.py", "app.rb", "server.php", "component.vue", "script.sh"]
      for file <- other_language_files do
        refute UnsafeRegex.applies_to_file?(file),
          "Should NOT apply to non-JavaScript file: #{file}"
      end
    end
    
    test "ast_enhancement/0 returns correct structure" do
      enhancement = UnsafeRegex.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      # Check AST rules
      assert is_map(enhancement.ast_rules)
      assert enhancement.ast_rules.node_type == "NewExpression"
      assert is_map(enhancement.ast_rules.regex_analysis)
      
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
    
    test "AST rules specify regex analysis patterns" do
      enhancement = UnsafeRegex.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "NewExpression"
      assert is_map(enhancement.ast_rules.regex_analysis)
      assert enhancement.ast_rules.regex_analysis.check_nested_quantifiers == true
      assert is_list(enhancement.ast_rules.regex_analysis.dangerous_patterns)
    end
    
    test "context rules exclude test files and check for safe patterns" do
      enhancement = UnsafeRegex.ast_enhancement()
      
      # Should exclude test directories
      exclude_paths = enhancement.context_rules.exclude_paths
      assert Enum.any?(exclude_paths, &Regex.match?(&1, "test/"))
      assert Enum.any?(exclude_paths, &Regex.match?(&1, "__mocks__/"))
      
      # Should have safe patterns
      assert is_list(enhancement.context_rules.safe_patterns)
      assert "sanitize-regex" in enhancement.context_rules.safe_patterns
      assert "safe-regex" in enhancement.context_rules.safe_patterns
    end
    
    test "confidence scoring adjusts for regex complexity" do
      enhancement = UnsafeRegex.ast_enhancement()
      
      adjustments = enhancement.confidence_rules.adjustments
      
      # Should have positive adjustments for dangerous patterns
      assert adjustments["nested_quantifiers"] > 0
      assert adjustments["overlapping_alternation"] > 0
      assert adjustments["unbounded_repetition"] > 0
      
      # Should have negative adjustments for safe patterns
      assert adjustments["bounded_quantifiers"] < 0
      assert adjustments["test_file"] < 0
      assert adjustments["safe_library"] < 0
    end
    
  end
end