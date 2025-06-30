defmodule RSOLVWeb.Router do
  use RSOLVWeb, :router
  require Logger

  # Pipelines
  pipeline :api do
    plug :accepts, ["json"]
    plug Plug.Parsers,
      parsers: [:json],
      pass: ["application/json"],
      json_decoder: Phoenix.json_library()
    plug :put_secure_browser_headers
  end
  
  pipeline :webhook do
    plug :accepts, ["json"]
    plug RSOLVWeb.Plugs.CaptureRawBody
    plug Plug.Parsers,
      parsers: [:json],
      pass: ["application/json"],
      json_decoder: Phoenix.json_library()
  end

  # Health check (outside versioned API)
  get "/health", RSOLVWeb.HealthController, :check

  # Webhook endpoints (separate from API versioning)
  scope "/webhook", RSOLVWeb do
    pipe_through :webhook
    
    post "/github", WebhookController, :github
  end

  # API v1
  scope "/api/v1", RSOLVWeb, as: :api_v1 do
    pipe_through :api

    # Core business resources
    resources "/fix-attempts", FixAttemptController, only: [:create]

    # Credential management
    scope "/credentials" do
      post "/exchange", CredentialController, :exchange
      post "/refresh", CredentialController, :refresh
    end

    # Usage tracking
    post "/usage/report", CredentialController, :report_usage

    # Security patterns
    scope "/patterns" do
      # Main pattern endpoints (access level determined by authentication)
      get "/", Api.V1.PatternController, :index
      get "/stats", Api.V1.PatternController, :stats
      
      # Pattern metadata endpoint
      get "/:id/metadata", PatternController, :metadata
    end

    # Educational features
    scope "/education" do
      post "/fix-completed", EducationController, :fix_completed
      get "/track-click/:alert_id", EducationController, :track_click
      get "/metrics", EducationController, :metrics
      get "/debug", EducationController, :debug
      get "/test-slack", EducationController, :test_slack
    end

    # Admin features  
    scope "/admin" do
      resources "/feature-flags", FeatureFlagController, 
        only: [:index, :show], 
        param: "flag_name"
    end
    
    # AST Analysis (RFC-031)
    scope "/ast" do
      post "/analyze", Api.V1.ASTController, :analyze
    end
    
    # Test endpoints removed - we don't use tiers anymore
  end

  # API v2 - Enhanced format by default
  scope "/api/v2", RSOLVWeb, as: :api_v2 do
    pipe_through :api

    # Security patterns with enhanced format by default
    scope "/patterns" do
      # Main pattern endpoint (returns enhanced format by default)
      get "/", Api.V1.PatternController, :index_v2
    end
  end
  
  # Prometheus metrics endpoint
  forward "/metrics", PromEx.Plug, prom_ex_module: RSOLV.PromEx
end