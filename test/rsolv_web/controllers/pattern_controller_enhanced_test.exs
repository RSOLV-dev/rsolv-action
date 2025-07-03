defmodule RsolvWeb.Api.V1.PatternControllerEnhancedTest do
  use RsolvWeb.ConnCase, async: false
  
  alias Rsolv.Security.Patterns.Javascript.EvalUserInput
  alias Rsolv.Security.Patterns.JSONSerializer

  describe "enhanced format" do
    test "includes AST enhancement fields", %{conn: conn} do
      # Test the pattern module directly first
      pattern = EvalUserInput.pattern()
      assert pattern.id == "js-eval-user-input"
      
      # Verify AST enhancement exists
      assert function_exported?(EvalUserInput, :ast_enhancement, 0)
      enhancement = EvalUserInput.ast_enhancement()
      
      assert enhancement.ast_rules
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.min_confidence == 0.8
      
      # Test JSON serialization
      enhanced_data = %{
        pattern: pattern,
        ast_rules: enhancement.ast_rules,
        context_rules: enhancement.context_rules,
        confidence_rules: enhancement.confidence_rules,
        min_confidence: enhancement.min_confidence
      }
      
      # Should encode without errors
      json_encoded = JSONSerializer.encode!(enhanced_data)
      assert is_binary(json_encoded)
      
      # Should contain serialized regex
      assert json_encoded =~ ~s("__type__":"regex")
      
      # Should decode back
      decoded = JSON.decode!(json_encoded)
      assert decoded["ast_rules"]
      assert decoded["context_rules"]["exclude_paths"]
    end
    
    test "GET /api/v1/patterns with enhanced format includes AST data", %{conn: conn} do
      # Request patterns with enhanced format
      conn = get(conn, ~p"/api/v1/patterns?language=javascript&format=enhanced")
      
      assert json_response(conn, 200)
      response = json_response(conn, 200)
      
      # Should have patterns
      assert patterns = response["patterns"]
      assert length(patterns) > 0
      
      # Find a pattern with AST enhancement
      eval_pattern = Enum.find(patterns, fn p -> 
        String.contains?(p["id"] || "", "eval")
      end)
      
      if eval_pattern do
        # Should have enhanced fields
        assert eval_pattern["ast_rules"] || eval_pattern["context_rules"] || eval_pattern["confidence_rules"],
               "Pattern should have at least one enhanced field"
        
        # If it has regex patterns, they should be serialized
        if eval_pattern["regex_patterns"] do
          pattern_json = JSON.encode!(eval_pattern)
          if pattern_json =~ "__type__" do
            assert pattern_json =~ ~s("__type__":"regex")
          end
        end
      end
    end
    
    test "standard format does not include AST data", %{conn: conn} do
      # Request patterns with standard format
      conn = get(conn, ~p"/api/v1/patterns?language=javascript&format=standard")
      
      assert json_response(conn, 200)
      response = json_response(conn, 200)
      
      # Should have patterns
      assert patterns = response["patterns"]
      assert length(patterns) > 0
      
      # Should NOT have enhanced fields
      pattern = List.first(patterns)
      refute pattern["ast_rules"]
      refute pattern["context_rules"] 
      refute pattern["confidence_rules"]
    end
  end
end