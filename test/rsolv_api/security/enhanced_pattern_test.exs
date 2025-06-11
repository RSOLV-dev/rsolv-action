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
        }
      }
      
      assert EnhancedPattern.valid?(pattern)
    end
    
    test "converts enhanced pattern to standard pattern" do
      enhanced = JavascriptEnhanced.sql_injection_enhanced()
      standard = EnhancedPattern.to_pattern(enhanced)
      
      assert %Pattern{} = standard
      assert standard.id == enhanced.id
      assert standard.name == enhanced.name
      assert standard.regex == enhanced.regex
      assert standard.test_cases == enhanced.test_cases
    end
    
    test "formats enhanced pattern for API with AST rules" do
      enhanced = JavascriptEnhanced.sql_injection_enhanced()
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
      pattern = JavascriptEnhanced.sql_injection_enhanced()
      
      assert pattern.id == "js-sql-injection-enhanced"
      assert length(pattern.ast_rules) >= 3
      assert pattern.context_rules != nil
      assert pattern.confidence_rules != nil
      assert pattern.enhanced_recommendation != nil
      
      # Check AST rule structure
      first_rule = hd(pattern.ast_rules)
      assert first_rule[:node_type] in [:binary_expression, :template_literal, :call_expression]
      assert is_map(first_rule[:properties])
    end
    
    test "missing_error_logging_enhanced detects catch blocks" do
      pattern = JavascriptEnhanced.missing_error_logging_enhanced()
      
      assert pattern.id == "js-missing-error-logging-enhanced"
      assert length(pattern.ast_rules) >= 2
      
      # Check for try-catch detection
      try_catch_rule = Enum.find(pattern.ast_rules, fn rule ->
        rule[:node_type] == :try_statement
      end)
      
      assert try_catch_rule != nil
      assert try_catch_rule[:properties][:handler] != nil
    end
    
    test "all patterns can be converted to standard format" do
      patterns = JavascriptEnhanced.all_as_patterns()
      
      assert length(patterns) > 0
      Enum.each(patterns, fn pattern ->
        assert %Pattern{} = pattern
        assert Pattern.valid?(pattern)
      end)
    end
  end
end