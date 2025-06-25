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
      
      # Check if any patterns have AST rules
      patterns_with_ast = Enum.filter(response["patterns"], fn pattern ->
        Map.has_key?(pattern, "astRules") && pattern["astRules"] != nil
      end)
      
      # At least some patterns should have AST rules
      assert length(patterns_with_ast) > 0, "No PHP patterns have AST rules"
      
      # Verify structure of AST rules
      Enum.each(patterns_with_ast, fn pattern ->
        assert is_list(pattern["astRules"]), "astRules should be a list for pattern #{pattern["id"]}"
        
        # Check that it's not using the old :rules format
        refute Map.has_key?(pattern, "rules"), "Pattern #{pattern["id"]} has 'rules' instead of 'astRules'"
        refute Map.has_key?(pattern, ":ast_rules"), "Pattern #{pattern["id"]} has atom key ':ast_rules'"
      end)
    end
    
    test "PHP command injection pattern has proper AST rules", %{conn: conn, test_customer: test_customer} do
      
      conn = conn
      |> put_req_header("authorization", "Bearer #{test_customer.api_key}")
      |> get("/api/v1/patterns?language=php&format=enhanced")
      
      assert response = json_response(conn, 200)
      
      # Find command injection pattern
      cmd_injection = Enum.find(response["patterns"], fn p -> 
        p["id"] == "php-command-injection"
      end)
      
      assert cmd_injection, "PHP command injection pattern not found"
      assert cmd_injection["astRules"], "PHP command injection has no AST rules"
      assert is_list(cmd_injection["astRules"]), "AST rules should be a list"
      
      # Verify AST rule structure
      first_rule = List.first(cmd_injection["astRules"])
      assert is_map(first_rule), "AST rule should be a map"
      assert Map.has_key?(first_rule, "type"), "AST rule should have type"
    end
    
    test "All PHP patterns with AST enhancement use correct format", %{conn: conn, test_customer: test_customer} do
      # List of PHP patterns that should have AST enhancement
      enhanced_patterns = [
        "php-command-injection",
        "php-sql-injection-concat",
        "php-sql-injection-interpolation",
        "php-xss-echo",
        "php-xss-print",
        "php-file-inclusion"
      ]
      
      conn = conn
      |> put_req_header("authorization", "Bearer #{test_customer.api_key}")
      |> get("/api/v1/patterns?language=php&format=enhanced")
      
      assert response = json_response(conn, 200)
      
      Enum.each(enhanced_patterns, fn pattern_id ->
        pattern = Enum.find(response["patterns"], fn p -> p["id"] == pattern_id end)
        
        assert pattern, "Pattern #{pattern_id} not found"
        assert pattern["supportsAst"] == true, "Pattern #{pattern_id} should support AST"
        assert pattern["astRules"], "Pattern #{pattern_id} should have astRules"
        assert is_list(pattern["astRules"]), "Pattern #{pattern_id} astRules should be a list"
        
        # Ensure no old format keys exist
        refute Map.has_key?(pattern, "rules"), "Pattern #{pattern_id} has old 'rules' key"
        refute Map.has_key?(pattern, ":ast_rules"), "Pattern #{pattern_id} has atom key"
      end)
    end
  end
end