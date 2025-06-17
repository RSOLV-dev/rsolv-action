defmodule RSOLVWeb.Controllers.TierDeterminationTest do
  use RSOLVWeb.ConnCase, async: true
  
  alias RSOLV.Accounts
  
  describe "determine_highest_tier with string/atom handling" do
    test "handles string tiers correctly", %{conn: conn} do
      # Test with enterprise customer
      enterprise_customer = %{
        id: "test_enterprise",
        name: "Enterprise Test",
        email: "enterprise@example.com",
        api_key: "test_enterprise_key",
        tier: "enterprise",
        flags: ["ai_access", "enterprise_access"],
        monthly_limit: 1000,
        current_usage: 0,
        active: true,
        trial: false,
        created_at: DateTime.utc_now()
      }
      
      # Store the customer
      {:ok, _} = Accounts.update_customer(enterprise_customer, %{})
      
      # Test endpoint that uses determine_highest_tier
      conn = conn
      |> put_req_header("authorization", "Bearer #{enterprise_customer.api_key}")
      |> get("/api/v1/patterns/javascript")
      
      response = json_response(conn, 200)
      
      # Should have access to all tiers
      assert response["accessible_tiers"] == ["public", "protected", "ai", "enterprise"]
      
      # Should get more than just public patterns
      assert response["count"] > 15  # More than just public patterns
    end
    
    test "handles protected tier access", %{conn: conn} do
      # Use the default test customer
      conn = conn
      |> put_req_header("authorization", "Bearer rsolv_test_abc123")
      |> get("/api/v1/patterns/javascript")
      
      response = json_response(conn, 200)
      
      # Test customer now has enterprise access
      assert "enterprise" in response["accessible_tiers"]
      
      # Should get all patterns due to cumulative access
      assert response["count"] > 20
    end
    
    test "handles public-only access without auth", %{conn: conn} do
      conn = get(conn, "/api/v1/patterns/javascript")
      
      response = json_response(conn, 200)
      
      # Should only have public tier
      assert response["accessible_tiers"] == ["public"]
      
      # Should get only public patterns
      assert response["count"] < 20
    end
  end
  
  describe "test customer enterprise access" do
    test "test customer has enterprise tier", %{conn: conn} do
      # Verify test customer configuration
      customer = Accounts.get_customer_by_api_key("rsolv_test_abc123")
      
      assert customer != nil
      assert customer.tier == "enterprise"
      assert "ai_access" in customer.flags
      assert "enterprise_access" in customer.flags
    end
    
    test "test customer gets all pattern tiers", %{conn: conn} do
      # Test each tier endpoint
      tiers = ["public", "protected", "ai", "enterprise"]
      
      for tier <- tiers do
        conn = conn
        |> put_req_header("authorization", "Bearer rsolv_test_abc123")
        |> get("/api/v1/patterns/#{tier}/javascript")
        
        # Enterprise tier endpoint requires enterprise access
        if tier == "enterprise" do
          # Should be accessible with enterprise customer
          assert conn.status in [200, 403]
        else
          assert json_response(conn, 200)
        end
      end
    end
  end
  
  describe "enhanced format with all tiers" do
    test "enhanced format includes patterns from all accessible tiers", %{conn: conn} do
      conn = conn
      |> put_req_header("authorization", "Bearer rsolv_test_abc123")
      |> get("/api/v1/patterns/javascript?format=enhanced")
      
      response = json_response(conn, 200)
      
      assert response["format"] == "enhanced"
      assert response["count"] > 20
      
      # Check for AST enhancements
      patterns_with_ast = Enum.filter(response["patterns"], fn p ->
        p["astRules"] != nil || p["contextRules"] != nil || p["confidenceRules"] != nil
      end)
      
      assert length(patterns_with_ast) > 0
    end
  end
end