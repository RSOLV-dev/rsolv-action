defmodule RSOLV.APIIntegrationTest do
  @moduledoc """
  Integration tests for production API endpoints
  """
  use RSOLVWeb.ConnCase
  
  @api_base_url "https://api.rsolv.dev"
  
  describe "Health Endpoint" do
    test "returns healthy status with all services" do
      response = HTTPoison.get!("#{@api_base_url}/health")
      
      assert response.status_code == 200
      
      body = Jason.decode!(response.body)
      assert body["status"] == "healthy"
      assert body["service"] == "rsolv-api"
      assert body["version"] == "0.1.0"
      
      # Verify all services are healthy
      assert body["services"]["database"] == "healthy"
      assert body["services"]["ai_providers"]["anthropic"] == "healthy"
      assert body["services"]["ai_providers"]["openai"] == "healthy"
      assert body["services"]["ai_providers"]["openrouter"] == "healthy"
      # Note: We use DETS for storage, not Redis
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
      
      assert {:ok, %{rows: [[count]]}} = RsolvApi.Repo.query(query)
      assert count > 0
    end
    
    test "migrations are up to date" do
      query = """
      SELECT version 
      FROM schema_migrations 
      ORDER BY version DESC 
      LIMIT 5
      """
      
      {:ok, result} = RsolvApi.Repo.query(query)
      versions = Enum.map(result.rows, fn [v] -> v end)
      
      # Verify our new migrations are present
      assert 20250602000001 in versions # CreateFixAttempts
      assert 20250602000002 in versions # AddTrialTrackingToCustomers
    end
  end
end