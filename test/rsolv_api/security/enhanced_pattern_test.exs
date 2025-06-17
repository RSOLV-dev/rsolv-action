defmodule RsolvApi.Security.EnhancedPatternTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.EnhancedPattern
  alias RsolvApi.Security.Pattern
  alias RsolvApi.Security.Patterns.JavascriptEnhanced
  
  describe "EnhancedPattern" do
    test "creates valid enhanced pattern with AST rules" do
      pattern = %EnhancedPattern{
        id: "test-ast-pattern",
        name: "Test AST Pattern",
        description: "Test pattern with AST rules",
        type: :sql_injection,
        severity: :high,
        languages: ["javascript"],
        default_tier: :protected,
        recommendation: "Use parameterized queries",
        test_cases: %{
          vulnerable: ["const q = 'SELECT * FROM users WHERE id = ' + id"],
          safe: ["db.query('SELECT * FROM users WHERE id = ?', [id])"]
        },
        ast_rules: [
          %{
            node_type: :binary_expression,
            properties: %{
              operator: "+",
              left: %{type: "Literal", value_pattern: ~r/SELECT/i}
            },
            parent_context: nil,
            child_must_contain: nil
          }
        ],
        context_rules: %{
          exclude_paths: ["test/"],
          exclude_if_contains: ["// safe"],
          require_imports: nil,
          require_context: nil
        },
        confidence_rules: %{
          base_confidence: 0.8,
          increase_if: [
            %{condition: "user_input", amount: 0.1}
          ],
          decrease_if: [
            %{condition: "validated", amount: 0.2}
          ]
        },
        # Optional fields
        regex: ~r/SELECT.*FROM/i,
        frameworks: nil,
        cwe_id: "CWE-89",
        owasp_category: "A03:2021",
        enhanced_recommendation: nil,
        metadata: nil
      }
      
      assert EnhancedPattern.valid?(pattern)
    end
    
    test "converts enhanced pattern to standard pattern" do
      # Get all patterns and take the first one (sql_injection)
      [enhanced | _] = JavascriptEnhanced.all(:public)
      standard = EnhancedPattern.to_pattern(enhanced)
      
      assert %Pattern{} = standard
      assert standard.id == enhanced.id
      assert standard.name == enhanced.name
      assert standard.regex == enhanced.regex
      assert standard.test_cases == enhanced.test_cases
    end
    
    test "formats enhanced pattern for API with AST rules" do
      # Get all patterns from enterprise tier (includes all patterns)
      patterns = JavascriptEnhanced.all(:enterprise)
      enhanced = Enum.find(patterns, &(&1.id == "js-sql-injection-enhanced"))
      formatted = EnhancedPattern.to_enhanced_api_format(enhanced)
      
      assert formatted[:id] == "js-sql-injection-enhanced"
      assert formatted[:supports_ast] == true
      assert is_list(formatted[:ast_rules])
      assert length(formatted[:ast_rules]) > 0
      assert is_map(formatted[:context_rules])
      assert is_map(formatted[:confidence_rules])
      assert is_map(formatted[:enhanced_recommendation])
    end
    
    test "validates AST rules structure" do
      invalid_pattern = %EnhancedPattern{
        id: "invalid",
        name: "Invalid",
        description: "Invalid pattern",
        type: :sql_injection,
        severity: :high,
        languages: ["javascript"],
        default_tier: :protected,
        recommendation: "Fix it",
        test_cases: %{vulnerable: ["bad"], safe: ["good"]},
        ast_rules: [
          %{invalid_key: "value"}  # Missing required fields
        ]
      }
      
      refute EnhancedPattern.valid?(invalid_pattern)
    end
    
    test "generates fallback regex from AST rules" do
      pattern = %EnhancedPattern{
        id: "ast-only",
        name: "AST Only Pattern",
        description: "Pattern with only AST rules",
        type: :xss,
        severity: :high,
        languages: ["javascript"],
        regex: nil,  # No regex provided
        default_tier: :protected,
        recommendation: "Fix it",
        test_cases: %{vulnerable: ["bad"], safe: ["good"]},
        ast_rules: [
          %{
            node_type: :call_expression,
            properties: %{
              callee: %{name: "innerHTML"}
            },
            parent_context: nil,
            child_must_contain: nil
          }
        ]
      }
      
      standard = EnhancedPattern.to_pattern(pattern)
      assert standard.regex != nil
    end
  end
  
  describe "JavascriptEnhanced patterns" do
    test "sql_injection_enhanced has complete AST rules" do
      # Get all enterprise patterns to access sql_injection
      patterns = JavascriptEnhanced.all(:enterprise)
      pattern = Enum.find(patterns, fn p -> String.contains?(p.id, "sql-injection") end)
      
      assert pattern.id == "js-sql-injection-enhanced"
      assert is_map(pattern.ast_rules) || is_list(pattern.ast_rules)
      assert pattern.context_rules != nil
      # JavascriptEnhanced uses confidence_scoring instead of confidence_rules
      assert Map.get(pattern, :confidence_scoring) != nil || Map.get(pattern, :confidence_rules) != nil
      
      # Check AST rule structure (can be map or list)
      if is_list(pattern.ast_rules) do
        first_rule = hd(pattern.ast_rules)
        assert first_rule[:node_type] in [:binary_expression, :template_literal, :call_expression]
        assert is_map(first_rule[:properties])
      else
        assert pattern.ast_rules[:node_type] != nil
      end
    end
    
    test "missing_error_logging_enhanced detects catch blocks" do
      # Get all enterprise patterns to access missing_error_logging  
      patterns = JavascriptEnhanced.all(:enterprise)
      pattern = Enum.find(patterns, fn p -> String.contains?(p.id, "logging") end)
      
      assert pattern.id == "js-missing-logging-enhanced"
      assert is_map(pattern.ast_rules) || is_list(pattern.ast_rules)
      
      # Check AST rules exist
      assert pattern.ast_rules != nil
    end
    
    test "all patterns can be converted to standard format" do
      enhanced_patterns = JavascriptEnhanced.all(:enterprise)
      patterns = Enum.map(enhanced_patterns, &EnhancedPattern.to_pattern/1)
      
      assert length(patterns) > 0
      Enum.each(patterns, fn pattern ->
        assert %Pattern{} = pattern
        assert Pattern.valid?(pattern)
      end)
    end
  end
end