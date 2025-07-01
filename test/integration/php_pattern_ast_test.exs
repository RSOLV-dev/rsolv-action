defmodule RsolvApi.Integration.PhpPatternAstTest do
  use RSOLVWeb.ConnCase, async: true
  
  @moduledoc """
  Integration test to verify PHP pattern AST enhancement fix.
  Tests that PHP patterns return properly formatted ast_rules in API responses.
  """
  
  setup do
    # Create test customers with API keys
    test_customer = %{
      id: "test_php_ast_customer",
      name: "Test PHP AST Customer",
      email: "phptest@example.com",
      api_key: "rsolv_test_php_ast_abc123",
      monthly_limit: 100,
      current_usage: 0,
      active: true,
      trial: true,
      created_at: DateTime.utc_now()
    }
    
    %{test_customer: test_customer}
  end
  
  describe "PHP pattern AST enhancement" do
    test "PHP patterns return ast_rules in enhanced format", %{conn: conn} do
      # Test without API key (demo patterns)
      conn = get(conn, "/api/v1/patterns?language=php&format=enhanced")
      
      assert response = json_response(conn, 200)
      assert response["metadata"]["language"] == "php"
      assert response["metadata"]["format"] == "enhanced"
      
      # Demo should return 3 PHP patterns
      assert length(response["patterns"]) == 3
      
      # All PHP demo patterns should have the enhanced format structure
      Enum.each(response["patterns"], fn pattern ->
        # Check basic pattern structure
        assert Map.has_key?(pattern, "id")
        assert Map.has_key?(pattern, "supportsAst")
        
        # If pattern supports AST, check the structure
        if pattern["supportsAst"] do
          assert Map.has_key?(pattern, "astRules"), "Pattern #{pattern["id"]} missing astRules"
          assert Map.has_key?(pattern, "contextRules"), "Pattern #{pattern["id"]} missing contextRules"
          assert Map.has_key?(pattern, "confidenceRules"), "Pattern #{pattern["id"]} missing confidenceRules"
          assert Map.has_key?(pattern, "minConfidence"), "Pattern #{pattern["id"]} missing minConfidence"
        end
        
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
    
    test "PHP demo patterns have AST enhancement fields", %{conn: conn} do
      # Test with demo patterns
      conn = get(conn, "/api/v1/patterns?language=php&format=enhanced")
      
      assert response = json_response(conn, 200)
      
      # All demo patterns should have AST enhancement
      Enum.each(response["patterns"], fn pattern ->
        pattern_id = pattern["id"]
        
        # All PHP patterns support AST
        assert pattern["supportsAst"] == true, "Pattern #{pattern_id} should support AST"
        
        # Check enhanced format fields exist
        assert Map.has_key?(pattern, "astRules"), "Pattern #{pattern_id} should have astRules"
        assert Map.has_key?(pattern, "contextRules"), "Pattern #{pattern_id} should have contextRules"
        assert Map.has_key?(pattern, "confidenceRules"), "Pattern #{pattern_id} should have confidenceRules"
        assert Map.has_key?(pattern, "minConfidence"), "Pattern #{pattern_id} should have minConfidence"
        
        # Ensure no old format keys exist
        refute Map.has_key?(pattern, "rules"), "Pattern #{pattern_id} has old 'rules' key"
        refute Map.has_key?(pattern, ":ast_rules"), "Pattern #{pattern_id} has atom key"
      end)
    end
  end
end