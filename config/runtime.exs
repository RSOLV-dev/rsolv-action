import Config

# Configure the database
database_config = [
  url: System.get_env("DATABASE_URL"),
  pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10")
]

# Only add SSL config in production or when explicitly set
database_config = 
  if config_env() == :prod || System.get_env("DATABASE_SSL") == "true" do
    Keyword.merge(database_config, [
      ssl: true,
      ssl_opts: [verify: :verify_none]
    ])
  else
    database_config
  end

config :rsolv_api, RSOLV.Repo, database_config

# Configure the endpoint
config :rsolv_api, RSOLVWeb.Endpoint,
  url: [host: System.get_env("PHX_HOST") || "localhost", port: 443, scheme: "https"],
  http: [port: String.to_integer(System.get_env("PORT") || "4000")],
  secret_key_base: System.get_env("SECRET_KEY_BASE"),
  server: true

# Configure AI provider keys
config :rsolv_api, :ai_providers,
  anthropic_api_key: System.get_env("ANTHROPIC_API_KEY"),
  openai_api_key: System.get_env("OPENAI_API_KEY"),
  openrouter_api_key: System.get_env("OPENROUTER_API_KEY"),
  ollama_base_url: System.get_env("OLLAMA_BASE_URL")

# Configure rate limiting
config :rsolv_api, :rate_limits,
  credential_exchange: {10, :minute},  # 10 requests per minute
  usage_report: {100, :minute}         # 100 reports per minute

# Configure credential TTL
config :rsolv_api, :credentials,
  default_ttl_minutes: 60,
  max_ttl_minutes: 240

# Email configuration (for expert reviews)
config :rsolv_api, RSOLV.Mailer,
  adapter: Bamboo.PostmarkAdapter,
  api_key: System.get_env("POSTMARK_API_KEY")

# Logger configuration
config :logger, :console,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

# Configure Phoenix LiveDashboard
config :rsolv_api, RSOLVWeb.Endpoint,
  live_view: [signing_salt: System.get_env("LIVE_VIEW_SALT")]

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