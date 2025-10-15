defmodule RsolvWeb.Plugs.FeatureFlagPlug do
  @moduledoc """
  Plug to check if a specific feature flag is enabled.

  This plug can be used in a router pipeline to restrict access to routes based on feature flags.
  If the specified feature flag is not enabled, the user will be redirected to a fallback URL.
  """

  import Plug.Conn
  import Phoenix.Controller
  require Logger
  alias Rsolv.FeatureFlags
  alias RsolvWeb.Services.Analytics

  def init(options) do
    # Get required options
    feature = Keyword.fetch!(options, :feature)
    fallback_url = Keyword.get(options, :fallback_url, "/")
    message = Keyword.get(options, :message, "This feature is currently unavailable.")

    %{
      feature: feature,
      fallback_url: fallback_url,
      message: message
    }
  end

  def call(conn, %{feature: feature, fallback_url: fallback_url, message: message}) do
    if FeatureFlags.enabled?(feature) do
      # Feature is enabled, continue with the request
      conn
    else
      # Feature is disabled, log the access attempt and redirect
      Analytics.track("feature_disabled_access", %{
        feature: feature,
        path: conn.request_path,
        method: conn.method,
        remote_ip: format_ip(conn.remote_ip)
      })

      Logger.info("Access attempt to disabled feature",
        metadata: %{
          feature: feature,
          path: conn.request_path,
          remote_ip: format_ip(conn.remote_ip)
        }
      )

      # Redirect with flash message
      conn
      |> put_flash(:info, message)
      |> redirect(to: fallback_url)
      |> halt()
    end
  end

  # Helper for formatting IP addresses in logs
  defp format_ip(ip) when is_tuple(ip) do
    ip
    |> Tuple.to_list()
    |> Enum.join(".")
  end

  defp format_ip(_), do: "unknown"

  # Make it easy to create pipelines for common features
  def admin_dashboard,
    do: init(feature: :admin_dashboard, message: "Admin dashboard is not available")

  def metrics_dashboard,
    do: init(feature: :metrics_dashboard, message: "Metrics dashboard is not available")

  def feedback_dashboard,
    do: init(feature: :feedback_dashboard, message: "Feedback dashboard is not available")
end
