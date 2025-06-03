defmodule RSOLVWeb.WebhookController do
  use RSOLVWeb, :controller
  
  alias RsolvApi.Webhooks.EventRouter
  require Logger

  @github_webhook_secret System.get_env("GITHUB_WEBHOOK_SECRET", "default_dev_secret")

  def github(conn, params) do
    # For tests, skip signature verification if test_mode is set
    skip_signature = conn.assigns[:test_mode] || false
    
    with {:ok, platform} <- extract_platform(conn),
         {:ok, signature} <- get_signature(conn),
         {:ok, raw_body} <- get_raw_body(conn),
         _ = Logger.debug("Raw body in controller: #{inspect(raw_body)}"),
         :ok <- maybe_verify_signature(skip_signature, platform, signature, raw_body),
         {:ok, result} <- EventRouter.route_event(platform, conn.req_headers, params) do
      
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
    # Check assigns first (for tests), then private (from plug)
    case conn.assigns[:raw_body] || conn.private[:raw_body] do
      nil -> {:error, :no_raw_body}
      body -> {:ok, body}
    end
  end
  
  defp maybe_verify_signature(true = _skip, _platform, _signature, _raw_body), do: :ok
  defp maybe_verify_signature(false, platform, signature, raw_body) do
    EventRouter.verify_signature(platform, signature, raw_body, @github_webhook_secret)
  end
end