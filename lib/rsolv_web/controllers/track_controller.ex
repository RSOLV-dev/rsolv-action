defmodule RsolvWeb.TrackController do
  use RsolvWeb, :controller
  require Logger
  alias RsolvWeb.Services.Analytics

  @doc """
  Receives tracking events from client-side JavaScript
  Using a standard REST controller (non-LiveView) for maximum compatibility
  """
  def track(conn, params) do
    # Extract tracking data from request
    event_type = params["type"] || "unknown"
    event_data = params["data"] || %{}

    # Attempt to parse JSON string data if needed
    event_data =
      case event_data do
        data when is_binary(data) ->
          case Jason.decode(data) do
            {:ok, parsed} -> parsed
            _ -> %{"raw_data" => data}
          end

        data when is_map(data) ->
          data

        _ ->
          %{}
      end

    # Get IP address (will be anonymized)
    ip_address = to_string(:inet_parse.ntoa(conn.remote_ip))

    # Add request metadata
    tracking_data =
      Map.merge(
        %{
          "ip_address" => ip_address,
          "user_agent" => List.first(get_req_header(conn, "user-agent") || []),
          "request_path" => conn.request_path
        },
        event_data
      )

    # Convert string keys to atoms for our internal tracking system
    tracking_data_atoms =
      for {key, val} <- tracking_data, into: %{} do
        {String.to_atom(key), val}
      end

    # Log the tracking event
    user_agent = Map.get(tracking_data, "user_agent", "unknown")
    Logger.info("Tracking event received: #{event_type} from #{user_agent}",
      metadata: %{
        tracking_data: inspect(tracking_data)
      }
    )

    # Route to the appropriate tracking function based on event type
    case event_type do
      "page_view" ->
        Analytics.track_page_view(
          Map.get(tracking_data, "page", "/"),
          Map.get(tracking_data, "referrer"),
          tracking_data_atoms
        )

      "form_submit" ->
        Analytics.track_form_submission(
          Map.get(tracking_data, "form_id", "unknown"),
          Map.get(tracking_data, "status", "submit"),
          tracking_data_atoms
        )

      "conversion" ->
        Analytics.track_conversion(
          Map.get(tracking_data, "conversion_type", "unknown"),
          tracking_data_atoms
        )

      "session_start" ->
        Analytics.track("session_start", tracking_data_atoms)

      "session_end" ->
        Analytics.track("session_end", tracking_data_atoms)

      "heartbeat" ->
        Analytics.track("heartbeat", tracking_data_atoms)

      "click" ->
        Analytics.track("click", tracking_data_atoms)

      "scroll_depth" ->
        Analytics.track("scroll_depth", tracking_data_atoms)

      "section_view" ->
        Analytics.track_section_view(
          Map.get(tracking_data, "section_id", "unknown"),
          Map.get(tracking_data, "duration"),
          tracking_data_atoms
        )

      "exit_intent" ->
        Analytics.track("exit_intent", tracking_data_atoms)

      # Default for custom events
      _ ->
        Analytics.track(event_type, tracking_data_atoms)
    end

    # Return a simple JSON response
    # Using 201 Created since we're creating a tracking record
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(201, Jason.encode!(%{success: true}))
  end
end
