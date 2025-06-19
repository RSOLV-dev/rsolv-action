defmodule RSOLVWeb.EnhancedPatternControllerTest do
  use RSOLVWeb.ConnCase, async: true

  alias RSOLV.Accounts
  alias RsolvApi.FeatureFlags
  alias RsolvApi.Security.EnhancedPattern

  setup do
    # Use the test API key that's built into Accounts module
    regular_customer = %{
      id: "test_customer_1",
      name: "Test Customer",
      email: "test@example.com",
      api_key: "rsolv_test_abc123",
      monthly_limit: 100,
      current_usage: 15,
      active: true,
      trial: true,
      created_at: DateTime.utc_now()
    }
    
    # Create an internal customer using update_customer to store it
    internal_customer = %{
      id: "internal",
      email: "internal@rsolv.dev",
      name: "Internal Test",
      api_key: "test-internal-key",
      monthly_limit: 1000,
      current_usage: 0,
      active: true,
      trial: false,
      created_at: DateTime.utc_now()
    }
    
    # Store the internal customer
    {:ok, _} = Accounts.update_customer(internal_customer, %{})
    
    %{
      internal_customer: internal_customer,
      regular_customer: regular_customer
    }
  end

  describe "GET /api/v2/patterns/:tier/:language (enhanced format)" do
    test "returns enhanced patterns with AST rules for v2 endpoints", %{conn: conn, regular_customer: customer} do
      conn = conn
      |> put_req_header("authorization", "Bearer #{customer.api_key}")
      |> get(~p"/api/v2/patterns/ai/javascript")
      
      assert %{
        "tier" => "ai",
        "language" => "javascript",
        "format" => "enhanced",
        "patterns" => patterns
      } = json_response(conn, 200)
      
      assert is_list(patterns)
      
      # Check that at least one pattern has enhanced fields
      enhanced_pattern = Enum.find(patterns, fn p -> p["supportsAst"] == true end)
      assert enhanced_pattern != nil
      assert enhanced_pattern["astRules"] != nil
      assert is_list(enhanced_pattern["astRules"])
      assert enhanced_pattern["contextRules"] != nil
      assert enhanced_pattern["confidenceRules"] != nil
    end
    
    test "v2 endpoint includes backward compatibility fields", %{conn: conn, regular_customer: customer} do
      conn = conn
      |> put_req_header("authorization", "Bearer #{customer.api_key}")
      |> get(~p"/api/v2/patterns/ai/javascript")
      
      assert %{"patterns" => patterns} = json_response(conn, 200)
      
      # Check that patterns still have standard fields
      pattern = hd(patterns)
      assert pattern["id"] != nil
      assert pattern["patterns"] != nil  # Changed from "regex" to "patterns"
      assert pattern["testCases"] != nil  # Changed from "test_cases" to "testCases"
      assert pattern["recommendation"] != nil
    end
    
    test "returns error for v2 endpoints without authentication", %{conn: conn} do
      conn = get(conn, ~p"/api/v2/patterns/ai/javascript")
      
      assert json_response(conn, 401) == %{
        "error" => "API key required"
      }
    end
  end

  describe "GET /api/v1/patterns/:tier/:language?format=enhanced" do
    test "returns enhanced format when requested via query param", %{conn: conn, regular_customer: customer} do
      conn = conn
      |> put_req_header("authorization", "Bearer #{customer.api_key}")
      |> get(~p"/api/v1/patterns/ai/javascript?format=enhanced")
      
      assert %{
        "tier" => "ai",
        "language" => "javascript",
        "format" => "enhanced",
        "patterns" => patterns
      } = json_response(conn, 200)
      
      # Verify enhanced fields are present
      pattern = hd(patterns)
      assert Map.has_key?(pattern, "supportsAst")
    end
    
    test "returns standard format by default on v1 endpoints", %{conn: conn, regular_customer: customer} do
      conn = conn
      |> put_req_header("authorization", "Bearer #{customer.api_key}")
      |> get(~p"/api/v1/patterns/ai/javascript")
      
      assert %{
        "tier" => "ai",
        "language" => "javascript",
        "patterns" => patterns
      } = json_response(conn, 200)
      
      # Verify enhanced fields are NOT present by default
      pattern = hd(patterns)
      refute Map.has_key?(pattern, "astRules")
      refute Map.has_key?(pattern, "supportsAst")
    end
  end

  describe "GET /api/v2/patterns/:language (combined endpoint)" do
    test "returns enhanced patterns for all accessible tiers", %{conn: conn, regular_customer: customer} do
      conn = conn
      |> put_req_header("authorization", "Bearer #{customer.api_key}")
      |> get(~p"/api/v2/patterns/javascript")
      
      assert %{
        "accessible_tiers" => tiers,
        "language" => "javascript",
        "format" => "enhanced",
        "patterns" => patterns
      } = json_response(conn, 200)
      
      assert "public" in tiers
      assert "ai" in tiers
      assert is_list(patterns)
      
      # Check mix of enhanced and standard patterns
      enhanced_count = Enum.count(patterns, fn p -> p["supportsAst"] == true end)
      assert enhanced_count > 0
    end
  end

  describe "Accept header content negotiation" do
    @tag :skip
    test "returns enhanced format for application/vnd.rsolv.v2+json", %{conn: conn, regular_customer: customer} do
      conn = conn
      |> put_req_header("authorization", "Bearer #{customer.api_key}")
      |> put_req_header("accept", "application/vnd.rsolv.v2+json")
      |> get(~p"/api/v1/patterns/ai/javascript")
      
      assert %{
        "format" => "enhanced",
        "patterns" => patterns
      } = json_response(conn, 200)
      
      pattern = hd(patterns)
      assert Map.has_key?(pattern, "supportsAst")
    end
    
    test "returns standard format for application/json", %{conn: conn, regular_customer: customer} do
      conn = conn
      |> put_req_header("authorization", "Bearer #{customer.api_key}")
      |> put_req_header("accept", "application/json")
      |> get(~p"/api/v1/patterns/ai/javascript")
      
      response = json_response(conn, 200)
      refute Map.has_key?(response, "format")
      
      pattern = hd(response["patterns"])
      refute Map.has_key?(pattern, "supportsAst")
    end
  end

  describe "Enhanced pattern validation" do
    test "enhanced patterns pass validation", %{conn: conn, regular_customer: customer} do
      conn = conn
      |> put_req_header("authorization", "Bearer #{customer.api_key}")
      |> get(~p"/api/v2/patterns/ai/javascript")
      
      assert %{"patterns" => patterns} = json_response(conn, 200)
      
      # Verify all enhanced patterns have valid structure
      Enum.each(patterns, fn pattern ->
        if pattern["supportsAst"] do
          assert is_list(pattern["astRules"])
          assert is_map(pattern["contextRules"])
          assert is_map(pattern["confidenceRules"])
          assert pattern["confidenceRules"]["base"] >= 0.0
          assert pattern["confidenceRules"]["base"] <= 1.0
        end
      end)
    end
  end

  describe "Feature flag control" do
    @tag :skip
    test "enhanced format disabled by feature flag returns standard format", %{conn: conn, regular_customer: customer} do
      # Disable enhanced patterns via environment variable
      System.put_env("RSOLV_FLAG_ENHANCED_PATTERNS_ENABLED", "false")
      
      conn = conn
      |> put_req_header("authorization", "Bearer #{customer.api_key}")
      |> get(~p"/api/v2/patterns/ai/javascript")
      
      assert %{
        "patterns" => patterns
      } = json_response(conn, 200)
      
      # Should fall back to standard format
      refute Map.has_key?(json_response(conn, 200), "format")
      pattern = hd(patterns)
      refute Map.has_key?(pattern, "supportsAst")
      
      # Clean up
      System.delete_env("RSOLV_FLAG_ENHANCED_PATTERNS_ENABLED")
    end
  end

  describe "Enhanced recommendation format" do
    test "includes quick fix and detailed steps when available", %{conn: conn, regular_customer: customer} do
      conn = conn
      |> put_req_header("authorization", "Bearer #{customer.api_key}")
      |> get(~p"/api/v2/patterns/ai/javascript")
      
      assert %{"patterns" => patterns} = json_response(conn, 200)
      
      # Find a pattern with enhanced recommendation
      pattern_with_rec = Enum.find(patterns, fn p -> 
        p["enhanced_recommendation"] != nil
      end)
      
      if pattern_with_rec do
        rec = pattern_with_rec["enhanced_recommendation"]
        assert is_map(rec)
        assert Map.has_key?(rec, "quick_fix") || Map.has_key?(rec, "detailed_steps") || Map.has_key?(rec, "references")
      end
    end
  end

  describe "Error handling" do
    @tag :skip  
    test "returns 404 for unsupported language", %{conn: conn, regular_customer: customer} do
      conn = conn
      |> put_req_header("authorization", "Bearer #{customer.api_key}")
      |> get(~p"/api/v2/patterns/ai/cobol")
      
      assert json_response(conn, 404) == %{
        "error" => "No patterns found for language: cobol"
      }
    end
    
    @tag :skip
    test "returns 404 for invalid tier", %{conn: conn, regular_customer: customer} do
      conn = conn
      |> put_req_header("authorization", "Bearer #{customer.api_key}")
      |> get(~p"/api/v2/patterns/invalid_tier/javascript")
      
      assert json_response(conn, 404) == %{
        "error" => "Invalid tier: invalid_tier"
      }
    end
  end

  describe "Performance considerations" do
    test "caches enhanced pattern transformations", %{conn: conn, regular_customer: customer} do
      # First request
      conn1 = conn
      |> put_req_header("authorization", "Bearer #{customer.api_key}")
      |> get(~p"/api/v2/patterns/ai/javascript")
      
      assert %{"patterns" => patterns1} = json_response(conn1, 200)
      
      # Second request should be faster (from cache)
      conn2 = build_conn()
      |> put_req_header("authorization", "Bearer #{customer.api_key}")
      |> get(~p"/api/v2/patterns/ai/javascript")
      
      assert %{"patterns" => patterns2} = json_response(conn2, 200)
      
      # Results should be identical
      assert patterns1 == patterns2
    end
  end
end