defmodule RsolvWeb.TrackController do
  use RsolvWeb, :controller
  require Logger
  alias RsolvWeb.Services.Analytics

  @doc """
  Receives tracking events from client-side JavaScript
  Using a standard REST controller (non-LiveView) for maximum compatibility
  """
  def track(conn, params) do
    event_type = params["type"] || "unknown"
    event_data = parse_event_data(params["data"])
    request_metadata = extract_request_metadata(conn)
    tracking_data = Map.merge(request_metadata, event_data)

    log_tracking_event(event_type, tracking_data)
    dispatch_tracking_event(event_type, tracking_data)

    conn
    |> put_status(:created)
    |> json(%{success: true})
  end

  # Private Helpers

  defp parse_event_data(nil), do: %{}
  defp parse_event_data(data) when is_map(data), do: data

  defp parse_event_data(data) when is_binary(data) do
    case JSON.decode(data) do
      {:ok, parsed} -> parsed
      {:error, _} -> %{"raw_data" => data}
    end
  end

  defp parse_event_data(_), do: %{}

  defp extract_request_metadata(conn) do
    %{
      "ip_address" => format_ip_address(conn.remote_ip),
      "user_agent" => get_user_agent(conn),
      "request_path" => conn.request_path
    }
  end

  defp format_ip_address(remote_ip) do
    remote_ip |> :inet_parse.ntoa() |> to_string()
  end

  defp get_user_agent(conn) do
    case get_req_header(conn, "user-agent") do
      [user_agent | _] -> user_agent
      [] -> nil
    end
  end

  defp log_tracking_event(event_type, tracking_data) do
    user_agent = Map.get(tracking_data, "user_agent", "unknown")

    Logger.info("Tracking event received: #{event_type} from #{user_agent}",
      metadata: %{tracking_data: inspect(tracking_data)}
    )
  end

  defp dispatch_tracking_event(event_type, tracking_data) do
    # Keep string keys - Analytics service will handle conversion
    case event_type do
      "page_view" ->
        Analytics.track_page_view(
          Map.get(tracking_data, "page", "/"),
          Map.get(tracking_data, "referrer"),
          tracking_data
        )

      "form_submit" ->
        Analytics.track_form_submission(
          Map.get(tracking_data, "form_id", "unknown"),
          Map.get(tracking_data, "status", "submit"),
          tracking_data
        )

      "conversion" ->
        Analytics.track_conversion(
          Map.get(tracking_data, "conversion_type", "unknown"),
          tracking_data
        )

      "section_view" ->
        Analytics.track_section_view(
          Map.get(tracking_data, "section_id", "unknown"),
          Map.get(tracking_data, "duration"),
          tracking_data
        )

      # All other events use the generic track function
      _ ->
        Analytics.track(event_type, tracking_data)
    end
  end
end
