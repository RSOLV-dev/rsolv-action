# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

config :rsolv,
  ecto_repos: [Rsolv.Repo]

# Configure Oban for background job processing
config :rsolv, Oban,
  repo: Rsolv.Repo,
  plugins: [Oban.Plugins.Pruner],
  queues: [default: 10, emails: 5]

# Configures the endpoint
config :rsolv, RsolvWeb.Endpoint,
  url: [host: "localhost"],
  render_errors: [
    formats: [html: RsolvWeb.ErrorHTML, json: RsolvWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: Rsolv.PubSub,
  live_view: [signing_salt: "changeme"]

# Configure esbuild (the version is required)
config :esbuild,
  version: "0.17.11",
  default: [
    args:
      ~w(js/app.js --bundle --target=es2017 --outdir=../priv/static/assets --external:/fonts/* --external:/images/* --external:react --external:react-dom/client --external:vibe-kanban-web-companion),
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
config :rsolv, Rsolv.PromEx,
  disabled: false,
  manual_metrics_start_delay: :no_delay,
  drop_metrics_groups: [],
  grafana: [
    host: System.get_env("GRAFANA_HOST", "http://localhost:3000"),
    auth_token: System.get_env("GRAFANA_AUTH_TOKEN", ""),
    upload_dashboards_on_start: true,
    folder_name: "Rsolv API Dashboards",
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

# Configure FunWithFlags
config :fun_with_flags, :persistence,
  adapter: FunWithFlags.Store.Persistent.Ecto,
  repo: Rsolv.Repo

# Enable cache-busting notifications with Phoenix.PubSub
config :fun_with_flags, :cache_bust_notifications,
  enabled: true,
  adapter: FunWithFlags.Notifications.PhoenixPubSub,
  client: Rsolv.PubSub

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"