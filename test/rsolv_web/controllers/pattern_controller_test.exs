defmodule RSOLVWeb.PatternControllerTest do
  use RSOLVWeb.ConnCase, async: true

  alias RSOLV.Accounts
  alias RsolvApi.FeatureFlags

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

  describe "public patterns" do
    test "returns public patterns without authentication", %{conn: conn} do
      conn = get(conn, ~p"/api/v1/patterns/public/javascript")
      
      assert json_response(conn, 200)
      assert %{
        "tier" => "public",
        "language" => "javascript",
        "patterns" => patterns
      } = json_response(conn, 200)
      
      assert is_list(patterns)
    end
    
    test "returns error when public patterns are disabled", %{conn: conn} do
      # Disable public patterns via environment variable
      System.put_env("RSOLV_FLAG_PATTERNS_PUBLIC_ENABLED", "false")
      
      conn = get(conn, ~p"/api/v1/patterns/public/javascript")
      
      assert json_response(conn, 403) == %{
        "error" => "Public patterns are currently disabled"
      }
      
      # Clean up
      System.delete_env("RSOLV_FLAG_PATTERNS_PUBLIC_ENABLED")
    end
  end

  describe "protected patterns" do
    test "returns error without authentication", %{conn: conn} do
      conn = get(conn, ~p"/api/v1/patterns/protected/javascript")
      
      assert json_response(conn, 401) == %{
        "error" => "API key required"
      }
    end
    
    test "returns error with invalid API key", %{conn: conn} do
      conn = conn
      |> put_req_header("authorization", "Bearer invalid-key")
      |> get(~p"/api/v1/patterns/protected/javascript")
      
      assert json_response(conn, 401) == %{
        "error" => "Invalid API key"
      }
    end
    
    test "returns protected patterns with valid API key", %{conn: conn, regular_customer: customer} do
      conn = conn
      |> put_req_header("authorization", "Bearer #{customer.api_key}")
      |> get(~p"/api/v1/patterns/protected/javascript")
      
      assert %{
        "tier" => "protected",
        "language" => "javascript",
        "patterns" => patterns
      } = json_response(conn, 200)
      
      assert is_list(patterns)
    end
  end

  describe "ai patterns" do
    test "returns error without authentication", %{conn: conn} do
      conn = get(conn, ~p"/api/v1/patterns/ai/javascript")
      
      assert json_response(conn, 401) == %{
        "error" => "API key required"
      }
    end
    
    test "returns ai patterns for authenticated users (default settings)", %{conn: conn, regular_customer: customer} do
      # By default, all authenticated users have AI access
      conn = conn
      |> put_req_header("authorization", "Bearer #{customer.api_key}")
      |> get(~p"/api/v1/patterns/ai/javascript")
      
      assert %{
        "tier" => "ai",
        "language" => "javascript",
        "patterns" => patterns
      } = json_response(conn, 200)
      
      assert is_list(patterns)
    end
    
    test "returns error when AI access is restricted", %{conn: conn, regular_customer: customer} do
      # Disable grant_all_authenticated
      System.put_env("RSOLV_FLAG_PATTERNS_AI_GRANT_ALL_AUTHENTICATED", "false")
      
      conn = conn
      |> put_req_header("authorization", "Bearer #{customer.api_key}")
      |> get(~p"/api/v1/patterns/ai/javascript")
      
      assert json_response(conn, 403) == %{
        "error" => "AI pattern access not enabled for this account"
      }
      
      # Clean up
      System.delete_env("RSOLV_FLAG_PATTERNS_AI_GRANT_ALL_AUTHENTICATED")
    end
  end

  describe "enterprise patterns" do
    test "returns error for regular users", %{conn: conn, regular_customer: customer} do
      conn = conn
      |> put_req_header("authorization", "Bearer #{customer.api_key}")
      |> get(~p"/api/v1/patterns/enterprise/javascript")
      
      assert json_response(conn, 403) == %{
        "error" => "Enterprise tier required"
      }
    end
    
    test "returns enterprise patterns for internal users", %{conn: conn, internal_customer: customer} do
      conn = conn
      |> put_req_header("authorization", "Bearer #{customer.api_key}")
      |> get(~p"/api/v1/patterns/enterprise/javascript")
      
      assert %{
        "tier" => "enterprise",
        "language" => "javascript",
        "patterns" => patterns
      } = json_response(conn, 200)
      
      assert is_list(patterns)
    end
  end

  describe "combined patterns by language" do
    test "returns only public patterns without authentication", %{conn: conn} do
      conn = get(conn, ~p"/api/v1/patterns/javascript")
      
      assert %{
        "accessible_tiers" => ["public"],
        "language" => "javascript",
        "patterns" => patterns
      } = json_response(conn, 200)
      
      assert is_list(patterns)
    end
    
    test "returns multiple tiers for authenticated users", %{conn: conn, regular_customer: customer} do
      conn = conn
      |> put_req_header("authorization", "Bearer #{customer.api_key}")
      |> get(~p"/api/v1/patterns/javascript")
      
      assert %{
        "accessible_tiers" => tiers,
        "language" => "javascript",
        "patterns" => patterns
      } = json_response(conn, 200)
      
      assert "public" in tiers
      assert "protected" in tiers
      assert "ai" in tiers
      assert is_list(patterns)
    end
    
    test "returns all tiers for internal users", %{conn: conn, internal_customer: customer} do
      conn = conn
      |> put_req_header("authorization", "Bearer #{customer.api_key}")
      |> get(~p"/api/v1/patterns/javascript")
      
      assert %{
        "accessible_tiers" => tiers,
        "language" => "javascript",
        "patterns" => patterns
      } = json_response(conn, 200)
      
      assert tiers == ["public", "protected", "ai", "enterprise"]
      assert is_list(patterns)
    end
  end
end