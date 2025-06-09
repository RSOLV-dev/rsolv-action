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

    # Security patterns - organized by access tier
    scope "/patterns" do
      # Public patterns (no authentication required)
      get "/public", PatternController, :all_public
      get "/public/:language", PatternController, :public
      
      # Protected patterns (require authentication in controller)
      get "/protected", PatternController, :all_protected
      get "/protected/:language", PatternController, :protected
      
      # AI patterns (require authentication + AI access in controller)
      get "/ai", PatternController, :all_ai
      get "/ai/:language", PatternController, :ai
      
      # Enterprise patterns (require authentication + enterprise access in controller)
      get "/enterprise", PatternController, :all_enterprise
      get "/enterprise/:language", PatternController, :enterprise
      
      # General patterns (access level determined by authentication in controller)
      get "/", PatternController, :all
      get "/:language", PatternController, :by_language
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
  end
end