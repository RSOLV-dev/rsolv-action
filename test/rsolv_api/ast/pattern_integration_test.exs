defmodule RsolvApi.AST.PatternIntegrationTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.AST.{ASTPatternMatcher, ConfidenceScorer, PatternAdapter}
  alias RsolvApi.Security.ASTPattern
  
  describe "end-to-end AST pattern matching" do
    test "detects SQL injection with high confidence and proper context" do
      # Python AST for: cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
      ast = %{
        "type" => "Module",
        "body" => [
          %{
            "type" => "Expr",
            "value" => %{
              "type" => "Call",
              "func" => %{
                "type" => "Attribute",
                "value" => %{"type" => "Name", "id" => "cursor"},
                "attr" => "execute"
              },
              "args" => [
                %{
                  "type" => "JoinedStr",
                  "values" => [
                    %{"type" => "Constant", "value" => "SELECT * FROM users WHERE id = "},
                    %{
                      "type" => "FormattedValue",
                      "value" => %{"type" => "Name", "id" => "user_id"}
                    }
                  ]
                }
              ]
            }
          }
        ]
      }
      
      # Get language-specific patterns from production system
      patterns = PatternAdapter.load_patterns_for_language("python")
      pattern = Enum.find(patterns, &(String.contains?(&1.id, "sql") && String.contains?(&1.id, "fstring")))
      
      # Match against AST
      {:ok, matches} = ASTPatternMatcher.match(ast, pattern, "python")
      
      # Should find the vulnerability
      assert length(matches) == 1
      match = hd(matches)
      
      # Calculate context-aware confidence
      context = %{
        pattern_type: :sql_injection,
        ast_match: :exact,
        has_user_input: true,
        in_database_call: true,
        framework_protection: false,
        file_path: "app/models/user.py"
      }
      
      confidence = ConfidenceScorer.calculate_confidence(context, "python", %{})
      
      # Should be high confidence  
      assert confidence >= 0.8
      assert match.confidence >= 0.7  # ASTPatternMatcher uses different scoring
      assert match.severity in ["medium", "high"]  # ASTPatternMatcher determines severity
    end
    
    test "reduces confidence for test files" do
      patterns = PatternAdapter.load_patterns_for_language("javascript")
      _pattern = Enum.find(patterns, &(String.contains?(&1.id, "eval")))
      
      # Test file context
      test_context = %{
        pattern_type: :code_injection,
        ast_match: :exact,
        has_user_input: true,
        file_path: "test/security_test.js"
      }
      
      # Production file context
      prod_context = %{
        pattern_type: :code_injection,
        ast_match: :exact,
        has_user_input: true,
        file_path: "src/user_controller.js"
      }
      
      test_confidence = ConfidenceScorer.calculate_confidence(test_context, "javascript", %{})
      prod_confidence = ConfidenceScorer.calculate_confidence(prod_context, "javascript", %{})
      
      assert test_confidence < prod_confidence
      assert test_confidence < 0.5  # Very low confidence in tests
    end
    
    test "enhances traditional patterns with AST rules" do
      # Start with a basic pattern
      basic_pattern = %RsolvApi.Security.Pattern{
        id: "js-sql-injection",
        name: "SQL Injection in JavaScript",
        type: :sql_injection,
        severity: :high,
        regex: ~r/SELECT.*FROM.*WHERE.*\+/,
        languages: ["javascript"],
        description: "Potential SQL injection",
        recommendation: "Use parameterized queries",
        test_cases: []
      }
      
      # Enhance with AST rules
      enhanced_pattern = ASTPattern.enhance(basic_pattern)
      
      assert enhanced_pattern.ast_rules != nil
      assert enhanced_pattern.context_rules != nil
      assert enhanced_pattern.confidence_rules != nil
      assert enhanced_pattern.min_confidence != nil
    end
    
    test "integrates with safe context detection" do
      # ORM usage should be safe - test with context analyzer instead
      context = RsolvApi.AST.ContextAnalyzer.analyze_code(
        "User.where(id: params[:id])", 
        "ruby",
        %{path: "app/models/user.rb"}
      )
      
      assert context.uses_orm == true
      
      # Parameterized queries should be safe - test with context analyzer
      param_context = RsolvApi.AST.ContextAnalyzer.analyze_code(
        "db.query('SELECT * FROM users WHERE id = ?', [id])", 
        "javascript",
        %{path: "app/controllers/users.js"}
      )
      
      assert param_context.uses_safe_patterns == true
      
      # Raw SQL concatenation should not be safe - test with context analyzer
      unsafe_context = RsolvApi.AST.ContextAnalyzer.analyze_code(
        "db.query('SELECT * FROM users WHERE id = ' + id)", 
        "javascript",
        %{path: "app/controllers/users.js"}
      )
      
      assert unsafe_context.uses_safe_patterns == false
    end
    
    test "provides comprehensive pattern coverage across languages" do
      # Should have patterns for multiple languages from production system
      python_patterns = PatternAdapter.load_patterns_for_language("python")
      ruby_patterns = PatternAdapter.load_patterns_for_language("ruby")
      js_patterns = PatternAdapter.load_patterns_for_language("javascript")
      php_patterns = PatternAdapter.load_patterns_for_language("php")
      java_patterns = PatternAdapter.load_patterns_for_language("java")
      go_patterns = PatternAdapter.load_patterns_for_language("go")
      
      # Filter for specific vulnerability types we care about
      python_sql = Enum.filter(python_patterns, &String.contains?(&1.id, "sql"))
      ruby_xss = Enum.filter(ruby_patterns, &String.contains?(&1.id, "xss"))
      js_eval = Enum.filter(js_patterns, &String.contains?(&1.id, "eval"))
      
      assert length(python_sql) > 0
      assert length(ruby_xss) > 0
      assert length(js_eval) > 0
      assert length(php_patterns) > 0
      assert length(java_patterns) > 0
      # Go patterns not yet implemented
      assert length(go_patterns) == 0
      
      # Each pattern should have all required fields
      all_patterns = python_patterns ++ ruby_patterns ++ js_patterns
      
      Enum.each(Enum.take(all_patterns, 10), fn pattern ->
        assert Map.has_key?(pattern, :id)
        assert Map.has_key?(pattern, :ast_pattern) || Map.has_key?(pattern, :regex)
        assert Map.has_key?(pattern, :min_confidence)
      end)
    end
    
    test "confidence explanation is informative" do
      context = %{
        pattern_type: :sql_injection,
        ast_match: :exact,
        has_user_input: true,
        framework_protection: false,
        file_path: "app/models/user.py"
      }
      
      explanation = ConfidenceScorer.explain_confidence(context, "python", %{})
      
      assert String.contains?(explanation, "Confidence score:")
      assert String.contains?(explanation, "User input detected")
      assert String.contains?(explanation, "Exact AST match")
      assert String.contains?(explanation, "%")
    end
  end
end