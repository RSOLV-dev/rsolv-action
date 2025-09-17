defmodule RsolvWeb.Plugs.ApiAuthenticationRegressionTest do
  @moduledoc """
  Regression tests for API authentication to prevent future authentication recognition issues.

  These tests specifically cover the scenarios that were broken before the fix:
  - API keys existing in database but not being recognized
  - Consistent authentication behavior across all controllers
  - Single code path validation
  """
  use RsolvWeb.ConnCase, async: true

  alias RsolvWeb.Plugs.ApiAuthentication
  alias Rsolv.Customers
  alias Rsolv.Accounts

  setup do
    # Create multiple customers with different API keys to test recognition
    {:ok, customer1} = Customers.create_customer(%{
      name: "Customer One",
      email: "customer1@example.com",
      monthly_limit: 100,
      current_usage: 0
    })

    {:ok, customer2} = Customers.create_customer(%{
      name: "Customer Two",
      email: "customer2@example.com",
      monthly_limit: 200,
      current_usage: 50
    })

    # Create API keys with different patterns
    api_key1 = "rsolv_test_#{:crypto.strong_rand_bytes(16) |> Base.encode64()}"
    api_key2 = "rsolv_prod_#{:crypto.strong_rand_bytes(16) |> Base.encode64()}"

    {:ok, api_key_record1} = Customers.create_api_key(customer1, %{
      key: api_key1,
      name: "Test API Key 1"
    })

    {:ok, api_key_record2} = Customers.create_api_key(customer2, %{
      key: api_key2,
      name: "Production API Key 2"
    })

    {:ok,
     customer1: customer1,
     customer2: customer2,
     api_key1: api_key1,
     api_key2: api_key2,
     api_key_record1: api_key_record1,
     api_key_record2: api_key_record2
    }
  end

  describe "regression: api key recognition issues" do
    test "prevents regression: API keys in database must be recognized", %{
      conn: conn,
      customer1: customer1,
      api_key1: api_key1
    } do
      # This was the core issue: API keys existed in DB but weren't recognized
      conn =
        conn
        |> put_req_header("x-api-key", api_key1)
        |> ApiAuthentication.call(false)

      assert conn.assigns.customer.id == customer1.id
      refute conn.halted
      assert conn.status != 401, "API key in database should be recognized, not rejected"
    end

    test "prevents regression: multiple different API keys work correctly", %{
      conn: conn,
      customer1: customer1,
      customer2: customer2,
      api_key1: api_key1,
      api_key2: api_key2
    } do
      # Test first API key
      conn1 =
        conn
        |> put_req_header("x-api-key", api_key1)
        |> ApiAuthentication.call(false)

      assert conn1.assigns.customer.id == customer1.id
      refute conn1.halted

      # Test second API key (fresh connection)
      conn2 =
        build_conn()
        |> put_req_header("x-api-key", api_key2)
        |> ApiAuthentication.call(false)

      assert conn2.assigns.customer.id == customer2.id
      refute conn2.halted
    end

    test "prevents regression: consistent behavior across connection resets", %{
      api_key1: api_key1,
      customer1: customer1
    } do
      # Test that authentication works consistently across multiple requests
      for _i <- 1..5 do
        conn =
          build_conn()
          |> put_req_header("x-api-key", api_key1)
          |> ApiAuthentication.call(false)

        assert conn.assigns.customer.id == customer1.id
        refute conn.halted
      end
    end

    test "prevents regression: invalid keys are still properly rejected", %{conn: conn} do
      # Ensure fix doesn't break invalid key rejection
      invalid_keys = [
        "invalid_key_123",
        "rsolv_fake_key",
        "not_in_database",
        "rsolv_" <> (:crypto.strong_rand_bytes(32) |> Base.encode64())
      ]

      for invalid_key <- invalid_keys do
        conn =
          build_conn()
          |> put_req_header("x-api-key", invalid_key)
          |> ApiAuthentication.call(false)

        assert conn.status == 401
        assert conn.halted

        resp = json_response(conn, 401)
        assert resp["error"] == "Invalid API key"
      end

      # Test empty string separately (gets treated as no key)
      conn =
        build_conn()
        |> put_req_header("x-api-key", "")
        |> ApiAuthentication.call(false)

      assert conn.status == 401
      assert conn.halted

      resp = json_response(conn, 401)
      assert resp["error"] == "Authentication required"
    end
  end

  describe "regression: single code path validation" do
    test "prevents regression: no Authorization Bearer fallback", %{conn: conn} do
      # Ensure we don't accidentally re-introduce Authorization Bearer support
      conn =
        conn
        |> put_req_header("authorization", "Bearer some_valid_token")
        |> ApiAuthentication.call(false)

      assert conn.status == 401
      assert conn.halted

      resp = json_response(conn, 401)
      assert resp["error"] == "Authentication required"
      assert resp["message"] =~ "x-api-key header"
    end

    test "prevents regression: only x-api-key header is used", %{
      conn: conn,
      api_key1: api_key1,
      customer1: customer1
    } do
      # Test that x-api-key works even with Authorization header present
      conn =
        conn
        |> put_req_header("x-api-key", api_key1)
        |> put_req_header("authorization", "Bearer some_other_token")
        |> ApiAuthentication.call(false)

      assert conn.assigns.customer.id == customer1.id
      refute conn.halted
    end
  end

  describe "regression: controller integration" do
    test "prevents regression: authentication works in controller pipeline", %{
      api_key1: api_key1,
      customer1: customer1
    } do
      # Simulate real controller usage
      conn =
        build_conn()
        |> put_req_header("x-api-key", api_key1)
        |> put_req_header("content-type", "application/json")

      # Apply the plug as controllers would
      conn = ApiAuthentication.call(conn, false)

      # Should be authenticated
      refute conn.halted
      assert conn.assigns.customer.id == customer1.id

      # Should be able to proceed to controller action
      assert is_map(conn.assigns.customer)
      assert conn.assigns.customer.name == "Customer One"
    end

    test "prevents regression: optional authentication mode works", %{
      api_key1: api_key1,
      customer1: customer1
    } do
      # Test optional mode with valid key
      conn1 =
        build_conn()
        |> put_req_header("x-api-key", api_key1)
        |> ApiAuthentication.call(true)

      assert conn1.assigns.customer.id == customer1.id
      refute conn1.halted

      # Test optional mode without key
      conn2 =
        build_conn()
        |> ApiAuthentication.call(true)

      refute Map.has_key?(conn2.assigns, :customer)
      refute conn2.halted

      # Test optional mode with invalid key (should still reject)
      conn3 =
        build_conn()
        |> put_req_header("x-api-key", "invalid_key")
        |> ApiAuthentication.call(true)

      assert conn3.status == 401
      assert conn3.halted
    end
  end

  describe "regression: database consistency" do
    test "prevents regression: active vs inactive API keys", %{
      customer1: customer1
    } do
      # Create an inactive API key
      inactive_key = "rsolv_inactive_#{:crypto.strong_rand_bytes(16) |> Base.encode64()}"
      {:ok, inactive_api_key} = Customers.create_api_key(customer1, %{
        key: inactive_key,
        name: "Inactive Key"
      })

      # Deactivate it
      Customers.update_api_key(inactive_api_key, %{active: false})

      # Should be rejected
      conn =
        build_conn()
        |> put_req_header("x-api-key", inactive_key)
        |> ApiAuthentication.call(false)

      assert conn.status == 401
      assert conn.halted
    end

    test "prevents regression: customer active status", %{
      api_key1: api_key1,
      customer1: customer1
    } do
      # Initially should work
      conn1 =
        build_conn()
        |> put_req_header("x-api-key", api_key1)
        |> ApiAuthentication.call(false)

      assert conn1.assigns.customer.id == customer1.id
      refute conn1.halted

      # Deactivate customer
      Customers.update_customer(customer1, %{active: false})

      # Should now be rejected
      conn2 =
        build_conn()
        |> put_req_header("x-api-key", api_key1)
        |> ApiAuthentication.call(false)

      assert conn2.status == 401
      assert conn2.halted
    end
  end
end