defmodule RsolvWeb.WebhookController do
  use RsolvWeb, :controller
  import Bitwise

  alias Rsolv.Webhooks.EventRouter
  alias Rsolv.Workers.StripeWebhookWorker
  require Logger

  # Get webhook secret at runtime, not compile time
  defp get_webhook_secret do
    System.get_env("GITHUB_WEBHOOK_SECRET", "default_dev_secret")
  end

  defp get_stripe_webhook_secret do
    System.get_env("STRIPE_WEBHOOK_SECRET", "whsec_test_secret_at_least_32_chars")
  end

  def stripe(conn, _params) do
    with {:ok, signature} <- get_stripe_signature(conn),
         {:ok, raw_body} <- get_raw_body(conn),
         :ok <- verify_stripe_signature(signature, raw_body, get_stripe_webhook_secret()),
         parsed_body <- get_parsed_body(conn, raw_body) do
      Logger.info("Stripe webhook received: #{inspect(parsed_body["type"])}")

      # Queue webhook for async processing via Oban
      queue_webhook_processing(parsed_body)

      # Return 200 immediately (Stripe requires response within ~30s)
      conn
      |> put_status(:ok)
      |> json(%{status: "success"})
    else
      {:error, :missing_signature} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Missing signature"})

      {:error, :invalid_signature} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Invalid signature"})

      {:error, :signature_expired} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Signature expired"})

      {:error, reason} ->
        Logger.error("Stripe webhook processing failed: #{inspect(reason)}")

        conn
        |> put_status(:bad_request)
        |> json(%{error: "Processing failed", reason: reason})
    end
  end

  def github(conn, _params) do
    # For tests, skip signature verification if test_mode is set
    skip_signature = conn.assigns[:test_mode] || false

    with {:ok, platform} <- extract_platform(conn),
         {:ok, signature} <- get_signature(conn),
         {:ok, raw_body} <- get_raw_body(conn),
         _ = Logger.debug("Raw body in controller: #{inspect(raw_body)}"),
         :ok <- maybe_verify_signature(skip_signature, platform, signature, raw_body),
         parsed_body <- get_parsed_body(conn, raw_body),
         {:ok, result} <- EventRouter.route_event(platform, conn.req_headers, parsed_body) do
      Logger.info("Webhook processed successfully: #{inspect(result)}")

      conn
      |> put_status(:ok)
      |> json(%{status: "success", result: result})
    else
      {:error, :missing_signature} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Missing signature"})

      {:error, :invalid_signature} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Invalid signature"})

      {:error, reason} ->
        Logger.error("Webhook processing failed: #{inspect(reason)}")

        conn
        |> put_status(:bad_request)
        |> json(%{error: "Processing failed", reason: reason})
    end
  end

  defp extract_platform(conn) do
    platform = EventRouter.extract_platform(conn.req_headers)
    {:ok, platform}
  end

  defp get_signature(conn) do
    case Plug.Conn.get_req_header(conn, "x-hub-signature-256") do
      [signature | _] -> {:ok, signature}
      [] -> {:error, :missing_signature}
    end
  end

  defp get_raw_body(conn) do
    # Check assigns first (for tests), then private (from plug), then reconstruct from params
    case conn.assigns[:raw_body] || conn.private[:raw_body] do
      nil ->
        # In test environment, reconstruct the JSON from params
        try do
          json = JSON.encode!(conn.params)
          {:ok, json}
        rescue
          _ -> {:error, :no_raw_body}
        end

      body ->
        {:ok, body}
    end
  end

  defp maybe_verify_signature(true = _skip, _platform, _signature, _raw_body), do: :ok

  defp maybe_verify_signature(false, platform, signature, raw_body) do
    EventRouter.verify_signature(platform, signature, raw_body, get_webhook_secret())
  end

  defp get_parsed_body(conn, raw_body) do
    # In test mode, prioritize conn.params if raw_body is empty or is a test placeholder
    if conn.assigns[:test_mode] &&
         (raw_body == "" || raw_body == nil || raw_body == "--plug_conn_test--") do
      # Use the parameters that Phoenix already parsed
      conn.params
    else
      parse_body(raw_body)
    end
  end

  defp parse_body(raw_body) when is_binary(raw_body) do
    case JSON.decode(raw_body) do
      {:ok, parsed} -> parsed
      {:error, _} -> %{}
    end
  end

  defp parse_body(_), do: %{}

  defp get_stripe_signature(conn) do
    case Plug.Conn.get_req_header(conn, "stripe-signature") do
      [signature | _] -> {:ok, signature}
      [] -> {:error, :missing_signature}
    end
  end

  defp verify_stripe_signature(signature_header, payload, secret) do
    with {:ok, timestamp, signature} <- parse_stripe_signature(signature_header),
         :ok <- verify_timestamp(timestamp),
         :ok <- verify_signature_match(timestamp, payload, signature, secret) do
      :ok
    end
  end

  defp parse_stripe_signature(header) do
    parts = String.split(header, ",")

    timestamp =
      parts
      |> Enum.find(&String.starts_with?(&1, "t="))
      |> case do
        "t=" <> ts when byte_size(ts) > 0 ->
          case Integer.parse(ts) do
            {int, ""} -> int
            _ -> nil
          end

        _ ->
          nil
      end

    signature =
      parts
      |> Enum.find(&String.starts_with?(&1, "v1="))
      |> case do
        "v1=" <> sig when byte_size(sig) > 0 -> sig
        _ -> nil
      end

    if timestamp && signature do
      {:ok, timestamp, signature}
    else
      {:error, :invalid_signature}
    end
  end

  defp verify_timestamp(timestamp) do
    current_time = System.system_time(:second)
    time_diff = abs(current_time - timestamp)

    # Allow 5 minute tolerance (300 seconds)
    if time_diff <= 300 do
      :ok
    else
      {:error, :signature_expired}
    end
  end

  defp verify_signature_match(timestamp, payload, expected_signature, secret) do
    signed_payload = "#{timestamp}.#{payload}"

    computed_signature =
      :crypto.mac(:hmac, :sha256, secret, signed_payload)
      |> Base.encode16(case: :lower)

    if secure_compare(computed_signature, expected_signature) do
      :ok
    else
      {:error, :invalid_signature}
    end
  end

  # Constant-time string comparison to prevent timing attacks
  defp secure_compare(a, b) when byte_size(a) == byte_size(b) do
    a
    |> :binary.bin_to_list()
    |> Enum.zip(:binary.bin_to_list(b))
    |> Enum.reduce(0, fn {x, y}, acc -> acc ||| Bitwise.bxor(x, y) end)
    |> Kernel.==(0)
  end

  defp secure_compare(_, _), do: false

  # Queue Stripe webhook for async processing
  defp queue_webhook_processing(event) do
    %{
      stripe_event_id: event["id"],
      event_type: event["type"],
      event_data: event["data"]
    }
    |> StripeWebhookWorker.new()
    |> Oban.insert()
  end
end
