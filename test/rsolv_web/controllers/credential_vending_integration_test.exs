defmodule RsolvWeb.CredentialVendingIntegrationTest do
  use RsolvWeb.ConnCase, async: false

  alias Rsolv.Credentials
  alias Rsolv.Accounts
  alias Rsolv.Customers
  alias Rsolv.Customers.Customer
  alias Rsolv.Customers.ApiKey
  alias Rsolv.Repo

  require Logger

  describe "credential vending full flow" do
    setup do
      # Reset credential storage between tests to prevent state leakage in CI shards
      Rsolv.Credentials.reset_credentials()

      # Create a real customer with database records
      unique_id = System.unique_integer([:positive])

      # Create customer directly
      {:ok, customer} =
        Customers.create_customer(%{
          name: "Test Customer #{unique_id}",
          email: "test#{unique_id}@example.com",
          monthly_limit: 100,
          current_usage: 15,
          trial: true,
          subscription_type: "standard"
        })

      # Create API key
      {:ok, api_key_result} =
        Customers.create_api_key(customer, %{
          name: "Test Key",
          permissions: ["full_access"]
        })

      # Extract raw key for use in headers
      {:ok, customer: customer, raw_api_key: api_key_result.raw_key}
    end

    test "should return API keys from environment or fallback", %{
      conn: conn,
      customer: _customer,
      raw_api_key: raw_api_key
    } do
      # Test credential exchange endpoint
      conn =
        conn
        |> put_req_header("content-type", "application/json")
        |> put_req_header("x-api-key", raw_api_key)
        |> post("/api/v1/credentials/exchange", %{
          "providers" => ["anthropic"],
          "ttl_minutes" => 60
        })

      assert json_response(conn, 200)
      response = json_response(conn, 200)

      # Verify response structure
      assert Map.has_key?(response, "credentials")
      assert Map.has_key?(response["credentials"], "anthropic")
      assert Map.has_key?(response["credentials"]["anthropic"], "api_key")

      # Verify the API key matches expected value (env var or fallback)
      vended_key = response["credentials"]["anthropic"]["api_key"]
      assert vended_key != nil, "Vended API key should not be nil"

      expected_key = System.get_env("ANTHROPIC_API_KEY") || System.get_env("anthropic-api-key") || "sk-ant-mock-key"
      assert vended_key == expected_key, "Vended key should match environment variable or fallback"
    end

    test "credentials module should return API keys from environment or fallback", %{
      customer: customer,
      raw_api_key: _raw_api_key
    } do
      # Test direct credential creation
      {:ok, credential} =
        Credentials.create_temporary_credential(%{
          customer_id: customer.id,
          provider: "anthropic",
          expires_at: DateTime.add(DateTime.utc_now(), 3600, :second),
          usage_limit: 100
        })

      assert credential.api_key != nil, "API key should not be nil"

      # Verify it matches the environment variable or fallback
      expected_key = System.get_env("ANTHROPIC_API_KEY") || System.get_env("anthropic-api-key") || "sk-ant-mock-key"
      assert credential.api_key == expected_key, "API key should match environment variable or fallback"
    end

    test "format_credentials should properly extract API keys", %{
      customer: customer,
      raw_api_key: _raw_api_key
    } do
      # Create a credential
      {:ok, credential} =
        Credentials.create_temporary_credential(%{
          customer_id: customer.id,
          provider: "anthropic",
          expires_at: DateTime.add(DateTime.utc_now(), 3600, :second),
          usage_limit: 100
        })

      # Format it like the controller does
      formatted = format_single_credential(credential)

      # Verify the credential has an API key
      assert formatted["anthropic"]["api_key"] != nil

      # Verify it matches what we expect from the environment or fallback
      expected_key = System.get_env("ANTHROPIC_API_KEY") || System.get_env("anthropic-api-key") || "sk-ant-mock-key"
      assert formatted["anthropic"]["api_key"] == expected_key,
        "Formatted API key should match environment variable or fallback"
    end

    test "should handle multiple providers", %{
      conn: conn,
      customer: _customer,
      raw_api_key: raw_api_key
    } do
      # Set up environment variables for multiple providers
      System.put_env("OPENAI_API_KEY", "sk-test-openai-key")
      System.put_env("OPENROUTER_API_KEY", "sk-or-test-key")

      conn =
        conn
        |> put_req_header("content-type", "application/json")
        |> put_req_header("x-api-key", raw_api_key)
        |> post("/api/v1/credentials/exchange", %{
          "providers" => ["anthropic", "openai", "openrouter"],
          "ttl_minutes" => 60
        })

      assert json_response(conn, 200)
      response = json_response(conn, 200)

      # Verify all providers have keys
      assert Map.has_key?(response["credentials"], "anthropic")
      assert Map.has_key?(response["credentials"], "openai")
      assert Map.has_key?(response["credentials"], "openrouter")

      # Verify all providers have non-nil keys
      for {provider, creds} <- response["credentials"] do
        assert creds["api_key"] != nil, "#{provider} API key should not be nil"
        assert is_binary(creds["api_key"]), "#{provider} API key should be a string"
      end

      # Verify they match the configured values
      assert response["credentials"]["openai"]["api_key"] == "sk-test-openai-key"
      assert response["credentials"]["openrouter"]["api_key"] == "sk-or-test-key"
    end

    test "should include GitHub metadata when headers are present", %{
      conn: conn,
      customer: customer,
      raw_api_key: raw_api_key
    } do
      conn =
        conn
        |> put_req_header("content-type", "application/json")
        |> put_req_header("x-api-key", raw_api_key)
        |> put_req_header("x-github-job", "test-job-123")
        |> put_req_header("x-github-run", "test-run-456")
        |> post("/api/v1/credentials/exchange", %{
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
