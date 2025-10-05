defmodule RsolvWeb.Plugs.ApiAuthenticationTest do
  use RsolvWeb.ConnCase, async: true

  alias RsolvWeb.Plugs.ApiAuthentication
  alias Rsolv.Customers
  alias Rsolv.Accounts

  setup do
    # Create a test customer with API key
    {:ok, customer} = Customers.create_customer(%{
      name: "Test Customer",
      email: "test@example.com",
      monthly_limit: 100,
      current_usage: 0
    })

    api_key = "test_api_key_#{:crypto.strong_rand_bytes(16) |> Base.encode64()}"

    {:ok, api_key_record} = Customers.create_api_key(customer, %{
      key: api_key,
      name: "Test API Key"
    })

    {:ok, customer: customer, api_key: api_key, api_key_record: api_key_record}
  end

  describe "authentication with required auth (default)" do
    test "authenticates successfully with x-api-key header", %{conn: conn, customer: customer, api_key: api_key} do
      conn =
        conn
        |> put_req_header("x-api-key", api_key)
        |> ApiAuthentication.call(false)

      assert conn.assigns.customer.id == customer.id
      refute conn.halted
    end

    test "stores both customer and api_key record on successful authentication", %{conn: conn, customer: customer, api_key: api_key, api_key_record: api_key_record} do
      conn =
        conn
        |> put_req_header("x-api-key", api_key)
        |> ApiAuthentication.call(false)

      # Verify customer is assigned
      assert conn.assigns.customer.id == customer.id

      # Verify API key record is also assigned
      assert conn.assigns.api_key.id == api_key_record.id
      assert conn.assigns.api_key.key == api_key
      assert conn.assigns.api_key.customer_id == customer.id

      refute conn.halted
    end

    test "rejects Authorization Bearer header (x-api-key only)", %{conn: conn} do
      conn =
        conn
        |> put_req_header("authorization", "Bearer some_api_key")
        |> ApiAuthentication.call(false)

      assert conn.status == 401
      assert conn.halted

      resp = json_response(conn, 401)
      assert resp["error"]["code"] == "AUTH_REQUIRED"
      assert resp["error"]["message"] =~ "x-api-key header"
      assert resp["requestId"]
    end

    test "ignores Authorization header when x-api-key is present", %{conn: conn, customer: customer, api_key: api_key} do
      conn =
        conn
        |> put_req_header("x-api-key", api_key)
        |> put_req_header("authorization", "Bearer some_other_key")
        |> ApiAuthentication.call(false)

      assert conn.assigns.customer.id == customer.id
      refute conn.halted
    end

    test "returns 401 when no API key provided", %{conn: conn} do
      conn = ApiAuthentication.call(conn, false)

      assert conn.status == 401
      assert conn.halted

      resp = json_response(conn, 401)
      assert resp["error"]["code"] == "AUTH_REQUIRED"
      assert resp["error"]["message"] =~ "API key must be provided"
      assert resp["requestId"]
    end

    test "returns 401 when invalid API key provided in x-api-key header", %{conn: conn} do
      conn =
        conn
        |> put_req_header("x-api-key", "invalid_key_123")
        |> ApiAuthentication.call(false)

      assert conn.status == 401
      assert conn.halted

      resp = json_response(conn, 401)
      assert resp["error"]["code"] == "INVALID_API_KEY"
      assert resp["error"]["message"] == "Invalid or expired API key"
      assert resp["requestId"]
    end

    test "returns 401 when only Authorization header provided (x-api-key required)", %{conn: conn} do
      conn =
        conn
        |> put_req_header("authorization", "Bearer valid_key_123")
        |> ApiAuthentication.call(false)

      assert conn.status == 401
      assert conn.halted

      resp = json_response(conn, 401)
      assert resp["error"]["code"] == "AUTH_REQUIRED"
      assert resp["error"]["message"] =~ "x-api-key header"
      assert resp["requestId"]
    end
  end

  describe "authentication with optional auth" do
    test "allows request without API key when optional", %{conn: conn} do
      conn = ApiAuthentication.call(conn, true)

      refute Map.has_key?(conn.assigns, :customer)
      refute conn.halted
    end

    test "authenticates successfully with valid key when optional", %{conn: conn, customer: customer, api_key: api_key} do
      conn =
        conn
        |> put_req_header("x-api-key", api_key)
        |> ApiAuthentication.call(true)

      assert conn.assigns.customer.id == customer.id
      refute conn.halted
    end

    test "still rejects invalid API key even when optional", %{conn: conn} do
      # This is important: even with optional auth, an invalid key should be rejected
      # to prevent accidental use of wrong keys
      conn =
        conn
        |> put_req_header("x-api-key", "invalid_key_123")
        |> ApiAuthentication.call(true)

      assert conn.status == 401
      assert conn.halted

      resp = json_response(conn, 401)
      assert resp["error"]["code"] == "INVALID_API_KEY"
      assert resp["error"]["message"] == "Invalid or expired API key"
      assert resp["requestId"]
    end
  end

  describe "init/1" do
    test "defaults to required authentication" do
      assert ApiAuthentication.init([]) == false
    end

    test "accepts optional: true" do
      assert ApiAuthentication.init(optional: true) == true
    end

    test "accepts optional: false" do
      assert ApiAuthentication.init(optional: false) == false
    end
  end

  describe "integration with controllers" do
    test "plug can be used in controller pipeline", %{conn: conn, api_key: api_key} do
      # Simulate a controller using the plug
      defmodule TestController do
        use Phoenix.Controller
        plug ApiAuthentication

        def index(conn, _params) do
          json(conn, %{customer_id: conn.assigns.customer.id})
        end
      end

      conn =
        conn
        |> put_req_header("x-api-key", api_key)
        |> ApiAuthentication.call(false)

      refute conn.halted
      assert conn.assigns.customer
    end
  end
end