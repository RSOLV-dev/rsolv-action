defmodule RsolvWeb.CredentialVendingIntegrationTest do
  use RsolvWeb.ConnCase
  
  alias Rsolv.Credentials
  alias Rsolv.Accounts
  
  require Logger
  
  @demo_customer %{
    id: "test_customer_1",
    name: "Test Customer",
    email: "test@example.com",
    api_key: "rsolv_test_abc123",
    monthly_limit: 100,
    current_usage: 15,
    active: true,
    trial: true,
    subscription_tier: "standard",
    created_at: DateTime.utc_now(),
    updated_at: DateTime.utc_now()
  }
  
  describe "credential vending full flow" do
    setup do
      # The demo customer is already available via the API key "rsolv_test_abc123"
      # as configured in LegacyAccounts
      {:ok, customer: @demo_customer}
    end
    
    test "should return real API keys when environment variables are set", %{conn: conn, customer: customer} do
      # Test that environment variables are properly loaded
      anthropic_key = System.get_env("ANTHROPIC_API_KEY")
      assert anthropic_key != nil, "ANTHROPIC_API_KEY environment variable must be set"
      refute String.contains?(anthropic_key, "mock"), "ANTHROPIC_API_KEY should not be a mock key"
      
      # Test credential exchange endpoint
      conn = post(conn, "/api/v1/credentials/exchange", %{
        "api_key" => customer.api_key,
        "providers" => ["anthropic"],
        "ttl_minutes" => 60
      })
      
      assert json_response(conn, 200)
      response = json_response(conn, 200)
      
      # Verify response structure
      assert Map.has_key?(response, "credentials")
      assert Map.has_key?(response["credentials"], "anthropic")
      assert Map.has_key?(response["credentials"]["anthropic"], "api_key")
      
      # Verify the API key is real, not mock
      vended_key = response["credentials"]["anthropic"]["api_key"]
      assert vended_key != nil, "Vended API key should not be nil"
      refute String.contains?(vended_key, "mock"), "Vended API key should not be a mock key"
      assert vended_key == anthropic_key, "Vended key should match environment variable"
    end
    
    test "credentials module should return real API keys", %{customer: customer} do
      # Test direct credential creation
      {:ok, credential} = Credentials.create_temporary_credential(%{
        customer_id: customer.id,
        provider: "anthropic",
        expires_at: DateTime.add(DateTime.utc_now(), 3600, :second),
        usage_limit: 100
      })
      
      assert credential.api_key != nil, "API key should not be nil"
      refute String.contains?(credential.api_key, "mock"), "API key should not be mock"
      
      # Verify it matches the environment variable
      expected_key = System.get_env("ANTHROPIC_API_KEY") || System.get_env("anthropic-api-key")
      assert credential.api_key == expected_key, "API key should match environment variable"
    end
    
    test "format_credentials should properly extract API keys", %{customer: customer} do
      # Create a credential
      {:ok, credential} = Credentials.create_temporary_credential(%{
        customer_id: customer.id,
        provider: "anthropic",
        expires_at: DateTime.add(DateTime.utc_now(), 3600, :second),
        usage_limit: 100
      })
      
      # Format it like the controller does
      formatted = format_single_credential(credential)
      
      assert formatted["anthropic"]["api_key"] != nil
      refute String.contains?(formatted["anthropic"]["api_key"], "mock")
    end
    
    test "should handle multiple providers", %{conn: conn, customer: customer} do
      # Set up environment variables for multiple providers
      System.put_env("OPENAI_API_KEY", "sk-test-openai-key")
      System.put_env("OPENROUTER_API_KEY", "sk-or-test-key")
      
      conn = post(conn, "/api/v1/credentials/exchange", %{
        "api_key" => customer.api_key,
        "providers" => ["anthropic", "openai", "openrouter"],
        "ttl_minutes" => 60
      })
      
      assert json_response(conn, 200)
      response = json_response(conn, 200)
      
      # Verify all providers have keys
      assert Map.has_key?(response["credentials"], "anthropic")
      assert Map.has_key?(response["credentials"], "openai")
      assert Map.has_key?(response["credentials"], "openrouter")
      
      # Verify none are mock keys
      for {provider, creds} <- response["credentials"] do
        assert creds["api_key"] != nil, "#{provider} API key should not be nil"
        refute String.contains?(creds["api_key"], "mock"), "#{provider} should not be a mock key"
      end
    end
    
    test "should include GitHub metadata when headers are present", %{conn: conn, customer: customer} do
      conn = conn
      |> put_req_header("x-github-job", "test-job-123")
      |> put_req_header("x-github-run", "test-run-456")
      |> post("/api/v1/credentials/exchange", %{
        "api_key" => customer.api_key,
        "providers" => ["anthropic"],
        "ttl_minutes" => 60
      })
      
      assert json_response(conn, 200)
      
      # Verify metadata was stored
      latest = Credentials.get_latest_credential(customer.id)
      assert latest.github_job_id == "test-job-123"
      assert latest.github_run_id == "test-run-456"
    end
  end
  
  # Helper function to mimic controller's format_credentials for single credential
  defp format_single_credential(credential) do
    %{
      credential.provider => %{
        "api_key" => credential.api_key || credential.encrypted_key,
        "expires_at" => DateTime.to_iso8601(credential.expires_at)
      }
    }
  end
end