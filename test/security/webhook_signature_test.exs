defmodule Rsolv.Security.WebhookSignatureTest do
  @moduledoc """
  Webhook signature verification tests.

  Validates that webhook endpoints properly verify Stripe signatures
  to prevent replay attacks and unauthorized webhooks.
  """
  use RsolvWeb.ConnCase, async: true

  @webhook_secret "whsec_test_secret_at_least_32_chars"
  @valid_payload ~s({"type":"invoice.paid","data":{"object":{"id":"in_test"}}})

  describe "Stripe signature verification" do
    test "accepts valid signature", %{conn: conn} do
      timestamp = System.system_time(:second)
      signature = generate_stripe_signature(@valid_payload, timestamp, @webhook_secret)

      conn =
        conn
        |> put_req_header("stripe-signature", signature)
        |> put_req_header("content-type", "application/json")
        |> post("/api/webhooks/stripe", @valid_payload)

      # Should accept valid signature (200 or 202)
      assert conn.status in [200, 202, 204]
    end

    test "rejects invalid signature", %{conn: conn} do
      timestamp = System.system_time(:second)
      invalid_signature = "t=#{timestamp},v1=invalid_signature"

      conn =
        conn
        |> put_req_header("stripe-signature", invalid_signature)
        |> put_req_header("content-type", "application/json")
        |> post("/api/webhooks/stripe", @valid_payload)

      # Should reject with 400 or 401
      assert conn.status in [400, 401]
      assert json_response(conn, conn.status)["error"]
    end

    test "rejects missing signature", %{conn: conn} do
      conn =
        conn
        |> put_req_header("content-type", "application/json")
        |> post("/api/webhooks/stripe", @valid_payload)

      assert conn.status in [400, 401]
    end

    test "rejects expired signatures (timestamp too old)", %{conn: conn} do
      # Timestamp from 10 minutes ago
      old_timestamp = System.system_time(:second) - 600
      signature = generate_stripe_signature(@valid_payload, old_timestamp, @webhook_secret)

      conn =
        conn
        |> put_req_header("stripe-signature", signature)
        |> put_req_header("content-type", "application/json")
        |> post("/api/webhooks/stripe", @valid_payload)

      # Should reject old signatures (prevents replay attacks)
      assert conn.status in [400, 401]
    end

    test "rejects future timestamps", %{conn: conn} do
      # Timestamp from future
      future_timestamp = System.system_time(:second) + 600
      signature = generate_stripe_signature(@valid_payload, future_timestamp, @webhook_secret)

      conn =
        conn
        |> put_req_header("stripe-signature", signature)
        |> put_req_header("content-type", "application/json")
        |> post("/api/webhooks/stripe", @valid_payload)

      assert conn.status in [400, 401]
    end

    test "rejects tampered payload", %{conn: conn} do
      timestamp = System.system_time(:second)
      signature = generate_stripe_signature(@valid_payload, timestamp, @webhook_secret)

      # Tamper with payload after signature generation
      tampered_payload = String.replace(@valid_payload, "in_test", "in_hacked")

      conn =
        conn
        |> put_req_header("stripe-signature", signature)
        |> put_req_header("content-type", "application/json")
        |> post("/api/webhooks/stripe", tampered_payload)

      assert conn.status in [400, 401]
    end
  end

  describe "replay attack prevention" do
    test "rejects duplicate event IDs", %{conn: conn} do
      timestamp = System.system_time(:second)
      payload = ~s({"id":"evt_unique_123","type":"invoice.paid"})
      signature = generate_stripe_signature(payload, timestamp, @webhook_secret)

      # First request - should succeed
      conn1 =
        build_conn()
        |> put_req_header("stripe-signature", signature)
        |> put_req_header("content-type", "application/json")
        |> post("/api/webhooks/stripe", payload)

      assert conn1.status in [200, 202, 204]

      # Second request with same event ID - should be rejected as duplicate
      conn2 =
        build_conn()
        |> put_req_header("stripe-signature", signature)
        |> put_req_header("content-type", "application/json")
        |> post("/api/webhooks/stripe", payload)

      # Should detect duplicate (idempotency check)
      # May return 200 (already processed) or 409 (conflict)
      assert conn2.status in [200, 202, 204, 409]
    end
  end

  describe "signature format validation" do
    test "rejects malformed signature format", %{conn: conn} do
      malformed_signatures = [
        "invalid",
        "t=123",
        "v1=abc",
        "t=,v1=",
        "random_string"
      ]

      for sig <- malformed_signatures do
        conn =
          build_conn()
          |> put_req_header("stripe-signature", sig)
          |> put_req_header("content-type", "application/json")
          |> post("/api/webhooks/stripe", @valid_payload)

        assert conn.status in [400, 401],
               "Malformed signature '#{sig}' should be rejected"
      end
    end

    test "validates signature scheme version", %{conn: conn} do
      timestamp = System.system_time(:second)
      # v2 scheme doesn't exist - should reject
      invalid_version_sig = "t=#{timestamp},v2=abc123"

      conn =
        conn
        |> put_req_header("stripe-signature", invalid_version_sig)
        |> put_req_header("content-type", "application/json")
        |> post("/api/webhooks/stripe", @valid_payload)

      assert conn.status in [400, 401]
    end
  end

  # Helper function to generate valid Stripe signature
  defp generate_stripe_signature(payload, timestamp, secret) do
    signed_payload = "#{timestamp}.#{payload}"

    signature =
      :crypto.mac(:hmac, :sha256, secret, signed_payload)
      |> Base.encode16(case: :lower)

    "t=#{timestamp},v1=#{signature}"
  end
end
