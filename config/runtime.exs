import Config

# Configure clustering
if config_env() == :prod do
  # Generate a unique node name based on pod name (injected by Kubernetes)
  node_basename = System.get_env("RELEASE_NODE") || "rsolv"
  pod_name = System.get_env("POD_NAME") || "#{node_basename}-#{:rand.uniform(999999)}"
  pod_namespace = System.get_env("POD_NAMESPACE") || "default"
  
  # Service name should match the headless service in Kubernetes
  service_name = System.get_env("CLUSTER_SERVICE_NAME") || "rsolv-api-headless"
  
  config :rsolv, :cluster,
    topologies: [
      k8s_dns: [
        strategy: Cluster.Strategy.Kubernetes.DNS,
        config: [
          service: service_name,
          namespace: pod_namespace,
          application_name: "rsolv",
          polling_interval: 5_000,
          mode: :ip
        ]
      ]
    ]
end

# Configure the database
database_config = [
  url: System.get_env("DATABASE_URL"),
  pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10")
]

# Only add SSL config when explicitly enabled or in production without explicit disable
database_config = 
  cond do
    System.get_env("DATABASE_SSL") == "false" ->
      # Explicitly disable SSL to override any URL parameters
      Keyword.merge(database_config, [
        ssl: false
      ])
    System.get_env("DATABASE_SSL") == "true" ->
      Keyword.merge(database_config, [
        ssl: true,
        ssl_opts: [verify: :verify_none]
      ])
    config_env() == :test ->
      # Test environment should default to no SSL unless explicitly enabled
      Keyword.merge(database_config, [
        ssl: false
      ])
    config_env() == :prod ->
      Keyword.merge(database_config, [
        ssl: true,
        ssl_opts: [verify: :verify_none]
      ])
    true ->
      database_config
  end

config :rsolv, Rsolv.Repo, database_config

# Configure FunWithFlags
config :fun_with_flags, :persistence,
  adapter: FunWithFlags.Store.Persistent.Ecto,
  repo: Rsolv.Repo

# Disable cache notifications to avoid Redis dependency
config :fun_with_flags, :cache_bust_notifications, enabled: false

# Configure the endpoint
if config_env() != :test do
  config :rsolv, RsolvWeb.Endpoint,
    url: [host: System.get_env("PHX_HOST") || "localhost", port: 443, scheme: "https"],
    http: [
      ip: {0, 0, 0, 0},
      port: String.to_integer(System.get_env("PORT") || "4000")
    ],
    secret_key_base: System.get_env("SECRET_KEY_BASE"),
    server: true
end

# Configure AI provider keys
config :rsolv, :ai_providers,
  anthropic_api_key: System.get_env("ANTHROPIC_API_KEY"),
  openai_api_key: System.get_env("OPENAI_API_KEY"),
  openrouter_api_key: System.get_env("OPENROUTER_API_KEY"),
  ollama_base_url: System.get_env("OLLAMA_BASE_URL")

# Configure rate limiting
config :rsolv, :rate_limits,
  credential_exchange: {10, :minute},  # 10 requests per minute
  usage_report: {100, :minute}         # 100 reports per minute

# Configure credential TTL
config :rsolv, :credentials,
  default_ttl_minutes: 60,
  max_ttl_minutes: 240

# Configure Kit (ConvertKit) integration - matching original structure
config :rsolv, :convertkit,
  api_key: System.get_env("KIT_API_KEY"),
  form_id: System.get_env("KIT_FORM_ID"),
  early_access_tag_id: System.get_env("KIT_EA_TAG_ID"),
  api_base_url: System.get_env("KIT_API_URL") || "https://api.convertkit.com/v3"

# Configure admin notification emails
config :rsolv,
  admin_emails: System.get_env("ADMIN_EMAILS", "") |> String.split(",", trim: true)

# Email configuration (for expert reviews)
config :rsolv, Rsolv.Mailer,
  adapter: Bamboo.PostmarkAdapter,
  api_key: System.get_env("POSTMARK_API_KEY")

# Logger configuration
config :logger, :console,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

# Configure Phoenix LiveDashboard
if config_env() != :test do
  config :rsolv, RsolvWeb.Endpoint,
    live_view: [signing_salt: System.get_env("LIVE_VIEW_SALT")]
end

# Sentry error tracking
if System.get_env("SENTRY_DSN") do
  config :sentry,
    dsn: System.get_env("SENTRY_DSN"),
    environment_name: System.get_env("SENTRY_ENV") || "production",
    enable_source_code_context: true,
    root_source_code_path: File.cwd!(),
    tags: %{
      env: System.get_env("SENTRY_ENV") || "production"
    }
end