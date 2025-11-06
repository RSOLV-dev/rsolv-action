defmodule RsolvWeb.Live.Concerns.PageTracking do
  @moduledoc """
  Common functionality for tracking page views and UTM parameters in LiveViews.

  Use this concern in LiveViews to automatically:
  - Assign UTM parameters from URL
  - Track page view analytics
  - Set up page-level metadata

  ## Usage

      defmodule MyLive do
        use RsolvWeb, :live_view
        import RsolvWeb.Live.Concerns.PageTracking

        @impl true
        def mount(params, _session, socket) do
          socket =
            socket
            |> assign(:page_title, "My Page")
            |> track_page_view(params, "/my-page")

          {:ok, socket}
        end
      end
  """

  alias RsolvWeb.Services.Analytics
  alias RsolvWeb.Helpers.TrackingHelper

  @doc """
  Assigns UTM parameters and tracks page view.

  ## Parameters

    - socket: LiveView socket
    - params: Mount params containing UTM parameters
    - path: Page path for analytics (e.g., "/pricing", "/landing")

  ## Returns

    Updated socket with UTM parameters assigned and page view tracked.
  """
  def track_page_view(socket, params, path) do
    socket = TrackingHelper.assign_utm_params(socket, params)

    # Track page view
    referrer = socket.assigns[:referrer]
    tracking_data = TrackingHelper.extract_tracking_data(socket)
    Analytics.track_page_view(path, referrer, tracking_data)

    socket
  end

  @doc """
  Tracks CTA click with destination and optional metadata.

  ## Parameters

    - socket: LiveView socket
    - destination: Where the CTA leads (e.g., "/signup", "/contact")
    - metadata: Additional tracking data (e.g., %{plan: "pro", cta_type: "pricing"})

  ## Returns

    Tuple {:noreply, socket} suitable for handle_event return value
  """
  def track_cta_click(socket, destination, metadata \\ %{}) do
    tracking_data =
      socket
      |> TrackingHelper.extract_tracking_data()
      |> Map.merge(Map.put(metadata, :destination, destination))

    Analytics.track("cta_click", tracking_data)
    {:noreply, socket}
  end
end
