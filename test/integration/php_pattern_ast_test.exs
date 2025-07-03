defmodule Rsolv.Integration.PhpPatternAstTest do
  use RsolvWeb.ConnCase, async: true
  
  @moduledoc """
  Integration test to verify PHP pattern AST enhancement fix.
  Tests that PHP patterns return properly formatted ast_rules in API responses.
  """
  
  setup do
    # Use the standard test API key that exists in test environment
    test_customer = %{
      api_key: "rsolv_test_abc123"
    }
    
    %{test_customer: test_customer}
  end
  
  describe "PHP pattern AST enhancement" do
    test "PHP patterns return ast_rules in enhanced format", %{conn: conn, test_customer: test_customer} do
      # Test WITH API key to get enhanced patterns
      conn = 
        conn
        |> put_req_header("authorization", "Bearer #{test_customer.api_key}")
        |> get("/api/v1/patterns?language=php&format=enhanced")
      
      assert response = json_response(conn, 200)
      assert response["metadata"]["language"] == "php"
      assert response["metadata"]["format"] == "enhanced"
      
      # Should return full PHP patterns with API key
      assert length(response["patterns"]) >= 3
      
      # All PHP patterns should have the enhanced format structure with API key
      Enum.each(response["patterns"], fn pattern ->
        # Check basic pattern structure
        assert Map.has_key?(pattern, "id")
        assert Map.has_key?(pattern, "supportsAst")
        
        # All patterns should have AST fields when authenticated with format=enhanced
        assert Map.has_key?(pattern, "astRules"), "Pattern #{pattern["id"]} missing astRules"
        assert Map.has_key?(pattern, "contextRules"), "Pattern #{pattern["id"]} missing contextRules"
        assert Map.has_key?(pattern, "confidenceRules"), "Pattern #{pattern["id"]} missing confidenceRules"
        assert Map.has_key?(pattern, "minConfidence"), "Pattern #{pattern["id"]} missing minConfidence"
        
        # Check that it's not using the old :rules format
        refute Map.has_key?(pattern, "rules"), "Pattern #{pattern["id"]} has 'rules' instead of 'astRules'"
        refute Map.has_key?(pattern, ":ast_rules"), "Pattern #{pattern["id"]} has atom key ':ast_rules'"
      end)
    end
    
    test "PHP demo patterns have expected IDs", %{conn: conn} do
      
      conn = get(conn, "/api/v1/patterns?language=php&format=enhanced")
      
      assert response = json_response(conn, 200)
      
      # Check that we have the expected demo patterns
      pattern_ids = Enum.map(response["patterns"], & &1["id"])
      
      # Demo patterns for PHP should include these
      expected_demo_ids = ["php-sql-injection-concat", "php-xss-echo", "php-file-inclusion"]
      
      Enum.each(expected_demo_ids, fn id ->
        assert id in pattern_ids, "Expected demo pattern #{id} not found"
      end)
    end
    
    test "PHP demo patterns do NOT have AST enhancement fields", %{conn: conn} do
      # Test WITHOUT API key (demo patterns)
      conn = get(conn, "/api/v1/patterns?language=php&format=enhanced")
      
      assert response = json_response(conn, 200)
      
      # Demo patterns should NOT have AST enhancement fields even with format=enhanced
      Enum.each(response["patterns"], fn pattern ->
        pattern_id = pattern["id"]
        
        # Demo patterns don't get AST enhancement fields even with format=enhanced
        refute Map.has_key?(pattern, "astRules"), "Demo pattern #{pattern_id} should NOT have astRules"
        refute Map.has_key?(pattern, "contextRules"), "Demo pattern #{pattern_id} should NOT have contextRules"
        refute Map.has_key?(pattern, "confidenceRules"), "Demo pattern #{pattern_id} should NOT have confidenceRules"
        refute Map.has_key?(pattern, "minConfidence"), "Demo pattern #{pattern_id} should NOT have minConfidence"
        # Note: supportsAst might still be present in standard format, just not the enhancement fields
        
        # Should have basic pattern fields
        assert Map.has_key?(pattern, "id")
        assert Map.has_key?(pattern, "name")
        assert Map.has_key?(pattern, "description")
      end)
    end
  end
end