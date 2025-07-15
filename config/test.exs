import Config

# Set environment to test
config :rsolv, :env, :test

# Configure your database
#
# The MIX_TEST_PARTITION environment variable can be used
# to provide built-in test partitioning in CI environment.
# Run `mix help test` for more information.
config :rsolv, Rsolv.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5432,
  database: "rsolv_api_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 10

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :rsolv, RsolvWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "test-secret-key-base-at-least-64-chars-long-abcdefghijklmnopqrstuvwxyz0123456789",
  server: false,
  live_view: [signing_salt: "test-liveview-salt"]

# Print only warnings and errors during test
config :logger, level: :debug

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime

# Configure Bamboo mailer for test environment
config :rsolv, Rsolv.Mailer,
  adapter: Bamboo.TestAdapter

# Configure ConvertKit for test environment
config :rsolv, :convertkit,
  api_key: "test_api_key",
  form_id: "test_form_id",
  api_base_url: "https://api.convertkit.com/v3"

# Use HTTP client mock in tests
config :rsolv, :http_client, Rsolv.HTTPClientMock

# Disable Oban queues in test
config :rsolv, Oban, testing: :inline

# Use mock parsers in test environment
config :rsolv, :use_mock_parsers, true

# Shorter timeouts for tests
config :rsolv, :parser_timeout, 5_000
config :rsolv, :session_timeout, 300_000  # 5 minutes

# Disable parser pool pre-warming in test
config :rsolv, Rsolv.AST.ParserPool,
  pre_warm: false,
  pool_size: 1

# Configure FunWithFlags for test environment
config :fun_with_flags, :persistence,
  adapter: FunWithFlags.Store.Persistent.Ecto,
  repo: Rsolv.Repo

config :fun_with_flags, :cache, enabled: false

# Disable cache bust notifications to avoid Redis dependency issues
config :fun_with_flags, :cache_bust_notifications, enabled: false

# Configure admin emails for testing
config :rsolv,
  admin_emails: ["admin@test.com"]