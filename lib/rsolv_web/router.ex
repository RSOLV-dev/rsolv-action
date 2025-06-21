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
      
      # Enhanced patterns with AST rules (requires authentication)
      get "/enhanced", PatternController, :all_enhanced
      get "/enhanced/:language", PatternController, :enhanced
      
      # General patterns (access level determined by authentication in controller)  
      get "/", Api.V1.PatternController, :index
      get "/:language", PatternController, :by_language
      
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
    
    # Test endpoints removed - we don't use tiers anymore
  end

  # API v2 - Enhanced format by default
  scope "/api/v2", RSOLVWeb, as: :api_v2 do
    pipe_through :api

    # Security patterns with enhanced format by default
    scope "/patterns" do
      # V2 routes automatically use enhanced format
      get "/protected/:language", PatternController, :v2_protected
      get "/ai/:language", PatternController, :v2_ai
      get "/enterprise/:language", PatternController, :v2_enterprise
      get "/public/:language", PatternController, :v2_public
      
      # Combined endpoint for all accessible tiers
      get "/:language", PatternController, :v2_by_language
    end
  end
  
  # Prometheus metrics endpoint
  forward "/metrics", PromEx.Plug, prom_ex_module: RSOLV.PromEx
end