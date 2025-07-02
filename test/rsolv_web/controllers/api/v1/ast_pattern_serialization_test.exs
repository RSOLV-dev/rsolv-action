defmodule RSOLVWeb.Api.V1.ASTPatternSerializationTest do
  use RSOLVWeb.ConnCase
  
  describe "GET /api/v1/patterns with format=enhanced - AST Serialization" do
    test "returns AST enhancement fields when format=enhanced with API key", %{conn: conn} do
      # RED: This test should fail initially because AST fields are not being serialized
      conn = 
        conn
        |> put_req_header("authorization", "Bearer rsolv_test_abc123")
        |> get("/api/v1/patterns?language=javascript&format=enhanced")
      
      assert %{
        "patterns" => patterns,
        "metadata" => metadata
      } = json_response(conn, 200)
      
      # Verify metadata indicates enhanced format
      assert metadata["format"] == "enhanced"
      assert metadata["enhanced"] == true
      
      # Should have patterns
      assert length(patterns) > 0
      
      # Find a pattern we know has AST enhancements (SQL injection concat)
      sql_injection_pattern = Enum.find(patterns, fn p -> 
        p["id"] == "js-sql-injection-concat"
      end)
      
      assert sql_injection_pattern, "Should find js-sql-injection-concat pattern"
      
      # Verify AST enhancement fields are present and not null (in camelCase)
      assert sql_injection_pattern["astRules"] != nil, "astRules should not be null"
      assert sql_injection_pattern["contextRules"] != nil, "contextRules should not be null"
      assert sql_injection_pattern["confidenceRules"] != nil, "confidenceRules should not be null"
      assert sql_injection_pattern["minConfidence"] != nil, "minConfidence should not be null"
      
      # Verify AST rules structure
      ast_rules = sql_injection_pattern["astRules"]
      assert ast_rules["node_type"] == "BinaryExpression"
      assert ast_rules["operator"] == "+"
      assert is_map(ast_rules["context_analysis"])
      assert is_map(ast_rules["ancestor_requirements"]) || ast_rules["ancestor_requirements"] == nil
      
      # Verify context rules structure
      context_rules = sql_injection_pattern["contextRules"]
      assert is_list(context_rules["exclude_paths"])
      assert context_rules["exclude_if_parameterized"] == true
      
      # Verify confidence rules structure
      confidence_rules = sql_injection_pattern["confidenceRules"]
      assert is_number(confidence_rules["base"])
      assert is_map(confidence_rules["adjustments"])
      
      # Verify min_confidence
      assert sql_injection_pattern["minConfidence"] == 0.8
      
      # Verify regex patterns are still properly serialized
      assert is_list(sql_injection_pattern["regexPatterns"])
      assert length(sql_injection_pattern["regexPatterns"]) > 0
    end
    
    test "returns standard format without AST fields when format=standard", %{conn: conn} do
      conn = 
        conn
        |> put_req_header("authorization", "Bearer rsolv_test_abc123")
        |> get("/api/v1/patterns?language=javascript&format=standard")
      
      assert %{
        "patterns" => patterns,
        "metadata" => metadata
      } = json_response(conn, 200)
      
      # Verify metadata indicates standard format
      assert metadata["format"] == "standard"
      assert metadata["enhanced"] == false
      
      # Find the same pattern
      sql_injection_pattern = Enum.find(patterns, fn p -> 
        p["id"] == "js-sql-injection-concat"
      end)
      
      assert sql_injection_pattern
      
      # AST fields should not be present in standard format
      refute Map.has_key?(sql_injection_pattern, "astRules")
      refute Map.has_key?(sql_injection_pattern, "contextRules")
      refute Map.has_key?(sql_injection_pattern, "confidenceRules")
      refute Map.has_key?(sql_injection_pattern, "minConfidence")
    end
    
    test "demo patterns without API key do not include AST enhancements", %{conn: conn} do
      # Even with format=enhanced, demo patterns should not include AST fields
      conn = get(conn, "/api/v1/patterns?language=javascript&format=enhanced")
      
      assert %{
        "patterns" => patterns,
        "metadata" => metadata
      } = json_response(conn, 200)
      
      # Should only have demo patterns
      assert length(patterns) <= 20
      assert metadata["access_level"] == "demo"
      
      # Demo patterns should not have AST fields
      Enum.each(patterns, fn pattern ->
        refute Map.has_key?(pattern, "astRules")
        refute Map.has_key?(pattern, "contextRules")
        refute Map.has_key?(pattern, "confidenceRules")
        refute Map.has_key?(pattern, "minConfidence")
      end)
    end
    
    test "all enhanced patterns have properly formatted regex", %{conn: conn} do
      conn = 
        conn
        |> put_req_header("authorization", "Bearer rsolv_test_abc123")
        |> get("/api/v1/patterns?language=javascript&format=enhanced")
      
      %{"patterns" => patterns} = json_response(conn, 200)
      
      # Every pattern should have regexPatterns as a list
      Enum.each(patterns, fn pattern ->
        assert is_list(pattern["regexPatterns"]), 
          "Pattern #{pattern["id"]} should have regexPatterns as a list"
        
        Enum.each(pattern["regexPatterns"], fn regex ->
          # Regex can be either a string or a map (for serialized regex objects)
          assert is_binary(regex) || is_map(regex), 
            "Pattern #{pattern["id"]} regex should be a string or map, got: #{inspect(regex)}"
        end)
      end)
    end
    
    test "enhanced patterns include all standard fields plus AST fields", %{conn: conn} do
      conn = 
        conn
        |> put_req_header("authorization", "Bearer rsolv_test_abc123")
        |> get("/api/v1/patterns?language=javascript&format=enhanced")
      
      %{"patterns" => patterns} = json_response(conn, 200)
      pattern = List.first(patterns)
      
      # Standard fields should be present
      assert pattern["id"]
      assert pattern["name"]
      assert pattern["description"]
      assert pattern["type"]
      assert pattern["severity"]
      assert pattern["languages"]
      assert pattern["regexPatterns"]
      assert pattern["cweId"]
      assert pattern["owaspCategory"]
      assert pattern["recommendation"]
      assert pattern["examples"]
      
      # Enhanced fields should also be present for patterns that have them
      if pattern["id"] == "js-sql-injection-concat" do
        assert pattern["astRules"]
        assert pattern["contextRules"]
        assert pattern["confidenceRules"]
        assert pattern["minConfidence"]
      end
    end
  end
end