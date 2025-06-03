defmodule RSOLVWeb.Router do
  use RSOLVWeb, :router
  require Logger

  pipeline :api do
    plug :accepts, ["json"]
    plug :read_raw_body
    plug Plug.Parsers,
      parsers: [:json],
      pass: ["application/json"],
      json_decoder: Phoenix.json_library()
    plug :put_secure_browser_headers
  end
  
  # Debug plug to capture raw body
  def read_raw_body(conn, _opts) do
    case Plug.Conn.read_body(conn) do
      {:ok, body, conn} ->
        Logger.info("Raw body read: #{inspect(body)}")
        Plug.Conn.assign(conn, :raw_body, body)
      {:more, _partial_body, conn} ->
        Logger.info("Partial body read")
        conn
    end
  end
  
  pipeline :webhook do
    plug :accepts, ["json"]
  end

  # API v1 routes
  scope "/api/v1", RSOLVWeb do
    pipe_through :api

    # Fix attempt tracking - for RSOLV-action to record PR creation
    post "/fix-attempts", FixAttemptController, :create

    # Credential vending endpoints
    post "/credentials/exchange", CredentialController, :exchange
    post "/credentials/refresh", CredentialController, :refresh
    
    # Usage tracking
    post "/usage/report", CredentialController, :report_usage
    
    # Existing endpoints
    post "/auth", AuthController, :authenticate
    get "/usage/:customer_id", UsageController, :show
    
    # Expert review endpoints
    post "/review/request", ReviewController, :create
    get "/review/:review_id", ReviewController, :show
    post "/review/:review_id/comment", ReviewController, :add_comment
    
    # Educational component endpoints
    post "/education/fix-completed", EducationController, :fix_completed
    get "/education/track-click/:alert_id", EducationController, :track_click
    get "/education/metrics", EducationController, :metrics
    get "/education/debug", EducationController, :debug
    get "/education/test-slack", EducationController, :test_slack
  end

  # Webhook endpoint for GitHub
  scope "/webhook", RSOLVWeb do
    pipe_through :webhook
    
    post "/github", WebhookController, :github
  end

  # Health check
  scope "/", RSOLVWeb do
    get "/health", HealthController, :check
  end
end