defmodule Rsolv.PromEx do
  use PromEx, otp_app: :rsolv

  alias PromEx.Plugins

  @impl true
  def plugins do
    [
      # PromEx built-in plugins
      Plugins.Application,
      Plugins.Beam,
      {Plugins.Phoenix, router: RsolvWeb.Router, endpoint: RsolvWeb.Endpoint},
      {Plugins.Ecto, otp_app: :rsolv, repos: [Rsolv.Repo]},
      Plugins.PhoenixLiveView,

      # RSOLV custom plugins
      Rsolv.PromEx.ValidationPlugin
      # TODO: Add custom plugin for rate limiter metrics after fixing metric name format
      # Rsolv.PromEx.RateLimiterPlugin
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

      # RSOLV custom dashboards
      {:otp_app, "grafana_dashboards/rfc-060-validation-metrics.json"}
      # TODO: Add custom dashboard after fixing plugin
      # {:otp_app, "grafana_dashboards/rate_limiter.json"}
    ]
  end
end