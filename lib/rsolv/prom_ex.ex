defmodule RSOLV.PromEx do
  use PromEx, otp_app: :rsolv_api

  alias PromEx.Plugins

  @impl true
  def plugins do
    [
      # PromEx built-in plugins
      Plugins.Application,
      Plugins.Beam,
      {Plugins.Phoenix, router: RSOLVWeb.Router, endpoint: RSOLVWeb.Endpoint},
      {Plugins.Ecto, otp_app: :rsolv_api, repos: [RsolvApi.Repo]},
      Plugins.PhoenixLiveView,
      
      # Custom plugin for rate limiter metrics
      RSOLV.PromEx.RateLimiterPlugin
    ]
  end

  @impl true
  def dashboard_assigns do
    [
      datasource_id: "prometheus",
      default_selected_interval: "30s"
    ]
  end

  @impl true
  def dashboards do
    [
      # PromEx built-in Grafana dashboards
      {:prom_ex, "application.json"},
      {:prom_ex, "beam.json"},
      {:prom_ex, "phoenix.json"},
      {:prom_ex, "ecto.json"},
      {:prom_ex, "phoenix_live_view.json"},
      
      # Custom dashboards
      {:otp_app, "grafana_dashboards/rate_limiter.json"}
    ]
  end
end