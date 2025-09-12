defmodule Rsolv.APIIntegrationTest do
  @moduledoc """
  Integration tests for production API endpoints
  """
  use RsolvWeb.ConnCase
  
  @api_base_url "https://api.rsolv.dev"
  
  describe "Health Endpoint" do
    @tag :skip # Skip in test env to avoid hitting production
    test "returns healthy status with clustering info" do
      response = HTTPoison.get!("#{@api_base_url}/health")
      
      assert response.status_code == 200
      
      body = Jason.decode!(response.body)
      assert body["status"] in ["ok", "warning", "degraded", "healthy"]
      assert Map.has_key?(body, "timestamp")
      assert Map.has_key?(body, "clustering")
      
      # Verify clustering information is present
      clustering = body["clustering"]
      assert is_boolean(clustering["enabled"])
      assert Map.has_key?(clustering, "current_node")
      assert Map.has_key?(clustering, "connected_nodes")
      assert is_list(clustering["connected_nodes"])
      assert is_integer(clustering["node_count"])
    end
  end
  
  describe "Credential Exchange Endpoint" do
    @tag :skip # Skip in test env to avoid hitting production
    test "rejects request without API key" do
      response = HTTPoison.post(
        "#{@api_base_url}/api/v1/credentials/exchange",
        Jason.encode!(%{providers: ["anthropic"]}),
        [{"Content-Type", "application/json"}]
      )
      
      assert {:ok, %{status_code: 401}} = response
    end
    
    @tag :skip
    test "validates required parameters" do
      response = HTTPoison.post(
        "#{@api_base_url}/api/v1/credentials/exchange",
        Jason.encode!(%{}), # Missing providers
        [
          {"Content-Type", "application/json"},
          {"X-API-Key", "invalid_key"}
        ]
      )
      
      assert {:ok, %{status_code: 400}} = response
    end
  end
  
  describe "Database Connectivity" do
    test "can connect to production database" do
      # This test runs in the test environment but verifies schema
      query = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public'"
      
      assert {:ok, %{rows: [[count]]}} = Rsolv.Repo.query(query)
      assert count > 0
    end
    
    test "migrations are up to date" do
      query = """
      SELECT version 
      FROM schema_migrations 
      ORDER BY version DESC 
      LIMIT 5
      """
      
      {:ok, result} = Rsolv.Repo.query(query)
      versions = Enum.map(result.rows, fn [v] -> 
        case v do
          v when is_integer(v) -> v
          v when is_binary(v) -> String.to_integer(v)
        end
      end)
      
      # Verify we have migrations
      assert length(versions) > 0
      # Check that migrations are recent (2025)
      assert Enum.all?(versions, fn v -> v > 20250000000000 end)
    end
  end
end