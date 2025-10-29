defmodule RsolvWeb.CredentialVendingTest do
  use RsolvWeb.ConnCase
  import Rsolv.APITestHelpers

  describe "credential vending" do
    setup do
      setup_api_auth()
    end

    test "exchanges valid API key for anthropic credentials", %{
      conn: conn,
      raw_api_key: raw_api_key
    } do
      conn =
        conn
        |> put_req_header("content-type", "application/json")
        |> put_req_header("x-api-key", raw_api_key)
        |> post("/api/v1/credentials/exchange", %{
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
      conn =
        conn
        |> put_req_header("content-type", "application/json")
        |> put_req_header("x-api-key", "invalid_key_12345")
        |> post("/api/v1/credentials/exchange", %{
          "providers" => ["anthropic"],
          "ttl_minutes" => 60
        })

      assert json_response(conn, 401)
      resp = json_response(conn, 401)
      assert resp["error"]["code"] == "INVALID_API_KEY"
      assert resp["error"]["message"] == "Invalid or expired API key"
      assert resp["requestId"]
    end

    test "validates providers parameter is present", %{conn: conn, raw_api_key: raw_api_key} do
      conn =
        conn
        |> put_req_header("content-type", "application/json")
        |> put_req_header("x-api-key", raw_api_key)
        |> post(
          "/api/v1/credentials/exchange",
          %{
            # Missing providers
          }
        )

      # OpenApiSpex returns 422 for missing required fields
      assert json_response(conn, 422)
    end
  end
end
