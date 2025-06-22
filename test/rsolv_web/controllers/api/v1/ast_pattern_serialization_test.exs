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
      
      # Verify AST enhancement fields are present and not null
      assert sql_injection_pattern["ast_rules"] != nil, "ast_rules should not be null"
      assert sql_injection_pattern["context_rules"] != nil, "context_rules should not be null"
      assert sql_injection_pattern["confidence_rules"] != nil, "confidence_rules should not be null"
      assert sql_injection_pattern["min_confidence"] != nil, "min_confidence should not be null"
      
      # Verify AST rules structure
      ast_rules = sql_injection_pattern["ast_rules"]
      assert ast_rules["node_type"] == "BinaryExpression"
      assert ast_rules["operator"] == "+"
      assert is_map(ast_rules["context_analysis"])
      assert is_map(ast_rules["ancestor_requirements"])
      
      # Verify context rules structure
      context_rules = sql_injection_pattern["context_rules"]
      assert is_list(context_rules["exclude_paths"])
      assert context_rules["exclude_if_parameterized"] == true
      
      # Verify confidence rules structure
      confidence_rules = sql_injection_pattern["confidence_rules"]
      assert is_number(confidence_rules["base"])
      assert is_map(confidence_rules["adjustments"])
      
      # Verify min_confidence
      assert sql_injection_pattern["min_confidence"] == 0.8
      
      # Verify regex patterns are still properly serialized
      assert is_list(sql_injection_pattern["regex_patterns"])
      assert length(sql_injection_pattern["regex_patterns"]) > 0
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
      refute Map.has_key?(sql_injection_pattern, "ast_rules")
      refute Map.has_key?(sql_injection_pattern, "context_rules")
      refute Map.has_key?(sql_injection_pattern, "confidence_rules")
      refute Map.has_key?(sql_injection_pattern, "min_confidence")
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
        refute Map.has_key?(pattern, "ast_rules")
        refute Map.has_key?(pattern, "context_rules")
        refute Map.has_key?(pattern, "confidence_rules")
        refute Map.has_key?(pattern, "min_confidence")
      end)
    end
    
    test "all enhanced patterns have properly formatted regex_patterns", %{conn: conn} do
      conn = 
        conn
        |> put_req_header("authorization", "Bearer rsolv_test_abc123")
        |> get("/api/v1/patterns?language=javascript&format=enhanced")
      
      %{"patterns" => patterns} = json_response(conn, 200)
      
      # Every pattern should have regex_patterns as a list of strings
      Enum.each(patterns, fn pattern ->
        assert is_list(pattern["regex_patterns"]), 
          "Pattern #{pattern["id"]} should have regex_patterns as a list"
        
        Enum.each(pattern["regex_patterns"], fn regex ->
          assert is_binary(regex), 
            "Pattern #{pattern["id"]} regex should be a string, got: #{inspect(regex)}"
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
      assert pattern["regex_patterns"]
      assert pattern["cwe_id"]
      assert pattern["owasp_category"]
      assert pattern["recommendation"]
      assert pattern["examples"]
      
      # Enhanced fields should also be present for patterns that have them
      if pattern["id"] == "js-sql-injection-concat" do
        assert pattern["ast_rules"]
        assert pattern["context_rules"]
        assert pattern["confidence_rules"]
        assert pattern["min_confidence"]
      end
    end
  end
end