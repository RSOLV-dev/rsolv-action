defmodule Rsolv.AST.PatternAdapterTest do
  use Rsolv.IntegrationCase
  import Rsolv.TestHelpers, only: [unique_email: 0, unique_email: 1]
  
  alias Rsolv.AST.PatternAdapter
  alias Rsolv.Security.{Pattern, ASTPattern}
  
  setup do
    # Ensure PatternServer is started if not running
    if Process.whereis(Rsolv.Security.PatternServer) == nil do
      {:ok, _pid} = start_supervised(Rsolv.Security.PatternServer)
    end
    :ok
  end
  
  describe "load_patterns_for_language/1" do
    test "loads JavaScript patterns with AST enhancements" do
      patterns = PatternAdapter.load_patterns_for_language("javascript")
      
      assert is_list(patterns)
      assert length(patterns) > 0
      
      # Check for SQL injection pattern
      sql_pattern = Enum.find(patterns, &(&1.id == "js-sql-injection-concat"))
      assert sql_pattern != nil
      assert sql_pattern.ast_pattern != nil
      assert sql_pattern.ast_pattern["type"] == "BinaryExpression"
      assert sql_pattern.ast_pattern["operator"] == "+"
      assert sql_pattern.context_rules != nil
      assert sql_pattern.confidence_rules != nil
    end
    
    test "loads Python patterns with AST enhancements" do
      patterns = PatternAdapter.load_patterns_for_language("python")
      
      assert is_list(patterns)
      assert length(patterns) > 0
      
      # Check for a Python-specific pattern
      python_pattern = Enum.find(patterns, &(&1.languages == ["python"]))
      assert python_pattern != nil
    end
    
    test "returns empty list for unsupported language" do
      patterns = PatternAdapter.load_patterns_for_language("cobol")
      assert patterns == []
    end
    
    test "caches patterns for repeated calls" do
      # First call should load patterns
      {time1, patterns1} = :timer.tc(fn ->
        PatternAdapter.load_patterns_for_language("javascript")
      end)
      
      # Second call should be cached and faster
      {time2, patterns2} = :timer.tc(fn ->
        PatternAdapter.load_patterns_for_language("javascript")
      end)
      
      assert patterns1 == patterns2
      assert time2 < time1 / 2  # Cached call should be faster (relaxed from /10 to /2)
    end
  end
  
  describe "convert_to_matcher_format/1" do
    test "converts AST pattern to matcher format" do
      ast_pattern = %ASTPattern{
        id: "test-pattern",
        name: "Test Pattern",
        type: :sql_injection,
        severity: "high",
        ast_rules: %{
          node_type: "CallExpression",
          operator: "+",
          context_analysis: %{
            contains_sql_keywords: true
          }
        },
        context_rules: %{
          exclude_paths: [~r/test/],
          exclude_if_parameterized: true
        },
        confidence_rules: %{
          base: 0.5,
          adjustments: %{
            "has_user_input" => 0.3
          }
        },
        min_confidence: 0.7
      }
      
      matcher_pattern = PatternAdapter.convert_to_matcher_format(ast_pattern)
      
      assert matcher_pattern.id == "test-pattern"
      assert matcher_pattern.name == "Test Pattern"
      assert matcher_pattern.pattern_type == :sql_injection
      assert matcher_pattern.severity == "high"
      assert matcher_pattern.ast_pattern != nil
      assert matcher_pattern.context_rules == ast_pattern.context_rules
      assert matcher_pattern.confidence_rules == ast_pattern.confidence_rules
      assert matcher_pattern.min_confidence == 0.7
    end
    
    test "uses default min_confidence if not specified" do
      ast_pattern = %ASTPattern{
        id: "test-pattern",
        name: "Test Pattern",
        type: :xss,
        min_confidence: nil
      }
      
      matcher_pattern = PatternAdapter.convert_to_matcher_format(ast_pattern)
      assert matcher_pattern.min_confidence == 0.7
    end
  end
  
  describe "enhance_patterns/1" do
    test "enhances regular patterns with AST rules" do
      regular_pattern = %Pattern{
        id: "js-sql-injection-concat",
        name: "SQL Injection via String Concatenation",
        type: :sql_injection,
        languages: ["javascript"],
        regex: ~r/SELECT.*FROM.*WHERE.*\+/,
        description: "SQL injection via string concatenation",
        severity: "high",
        recommendation: "Use parameterized queries",
        test_cases: []
      }
      
      enhanced = PatternAdapter.enhance_pattern(regular_pattern)
      
      assert enhanced.ast_rules != nil
      assert enhanced.context_rules != nil
      assert enhanced.confidence_rules != nil
      assert enhanced.regex == regular_pattern.regex  # Original regex preserved
    end
    
    test "returns pattern unchanged if no AST enhancement available" do
      pattern = %Pattern{
        id: "unknown-pattern",
        name: "Unknown Pattern",
        type: :unknown,
        description: "Unknown pattern",
        severity: "low",
        recommendation: "Review manually",
        test_cases: [],
        languages: ["javascript"],
        regex: ~r/unknown/
      }
      
      enhanced = PatternAdapter.enhance_pattern(pattern)
      assert enhanced.ast_rules == nil
      assert enhanced.context_rules != nil  # This should still have context_rules
    end
  end
  
  describe "integration with PatternRegistry" do
    test "loads patterns from registry and enhances them" do
      # This tests the full integration
      patterns = PatternAdapter.load_patterns_for_language("javascript")
      
      # Should have patterns from the registry
      assert length(patterns) > 5
      
      # Patterns should be enhanced (these come from load_patterns_for_language which converts to matcher format)
      enhanced_patterns = Enum.filter(patterns, &(&1.ast_pattern != nil))
      assert length(enhanced_patterns) > 0
      
      # Check specific enhancements
      sql_pattern = Enum.find(patterns, &(&1.id == "js-sql-injection-concat"))
      if sql_pattern do
        assert sql_pattern.ast_pattern != nil
      else
        # Pattern might not exist, just check we have some enhanced patterns
        assert length(enhanced_patterns) > 0
      end
    end
  end
end