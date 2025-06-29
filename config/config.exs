# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

config :rsolv_api,
  ecto_repos: [RsolvApi.Repo]

# Configures the endpoint
config :rsolv_api, RSOLVWeb.Endpoint,
  url: [host: "localhost"],
  render_errors: [
    formats: [html: RSOLVWeb.ErrorHTML, json: RSOLVWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: RSOLV.PubSub,
  live_view: [signing_salt: "changeme"]

# Configure esbuild (the version is required)
config :esbuild,
  version: "0.17.11",
  default: [
    args:
      ~w(js/app.js --bundle --target=es2017 --outdir=../priv/static/assets --external:/fonts/* --external:/images/*),
    cd: Path.expand("../assets", __DIR__),
    env: %{"NODE_PATH" => Path.expand("../deps", __DIR__)}
  ]

# Configure tailwind (the version is required)
config :tailwind,
  version: "3.4.0",
  default: [
    args: ~w(
      --config=tailwind.config.js
      --input=css/app.css
      --output=../priv/static/assets/app.css
    ),
    cd: Path.expand("../assets", __DIR__)
  ]

# Configures Elixir's Logger
config :logger, :console,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

# Use native JSON module (Elixir 1.18+) for JSON parsing in Phoenix
config :phoenix, :json_library, JSON

# Configure PromEx for Prometheus metrics
config :rsolv_api, RSOLV.PromEx,
  disabled: false,
  manual_metrics_start_delay: :no_delay,
  drop_metrics_groups: [],
  grafana: [
    host: System.get_env("GRAFANA_HOST", "http://localhost:3000"),
    auth_token: System.get_env("GRAFANA_AUTH_TOKEN", ""),
    upload_dashboards_on_start: true,
    folder_name: "RSOLV API Dashboards",
    annotate_app_lifecycle: true
  ],
  metrics_server: [
    port: 4021,
    path: "/metrics",
    protocol: :http,
    pool_size: 5,
    cowboy_opts: [],
    auth_strategy: :none
  ]

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"