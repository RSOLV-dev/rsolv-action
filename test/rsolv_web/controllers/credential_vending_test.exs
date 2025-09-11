defmodule RsolvWeb.CredentialVendingTest do
  use RsolvWeb.ConnCase
  import Rsolv.APITestHelpers

  describe "credential vending" do
    setup do
      setup_api_auth()
    end

    test "exchanges valid API key for anthropic credentials", %{conn: conn, api_key: api_key} do
      conn = post(conn, "/api/v1/credentials/exchange", %{
        "api_key" => api_key.key,
        "providers" => ["anthropic"],
        "ttl_minutes" => 60
      })

      # This should pass with proper implementation
      assert response = json_response(conn, 200)
      assert Map.has_key?(response, "credentials")
      assert Map.has_key?(response["credentials"], "anthropic")
      assert Map.has_key?(response["credentials"]["anthropic"], "api_key")
      assert Map.has_key?(response["credentials"]["anthropic"], "expires_at")
    end

    test "returns 401 for invalid API key", %{conn: conn} do
      conn = post(conn, "/api/v1/credentials/exchange", %{
        "api_key" => "invalid_key_12345",
        "providers" => ["anthropic"],
        "ttl_minutes" => 60
      })

      assert json_response(conn, 401)
      assert %{"error" => "Invalid API key"} = json_response(conn, 401)
    end

    test "validates providers parameter is present", %{conn: conn, api_key: api_key} do
      conn = post(conn, "/api/v1/credentials/exchange", %{
        "api_key" => api_key.key
        # Missing providers
      })

      assert json_response(conn, 400)
    end
  end
end