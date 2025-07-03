defmodule RsolvWeb.Router do
  use RsolvWeb, :router
  import Phoenix.LiveView.Router
  require Logger

  # Pipelines
  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {RsolvWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

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
    plug RsolvWeb.Plugs.CaptureRawBody
    plug Plug.Parsers,
      parsers: [:json],
      pass: ["application/json"],
      json_decoder: Phoenix.json_library()
  end

  # Health check (outside versioned API)
  get "/health", RsolvWeb.HealthController, :check

  # Web routes
  scope "/" do
    pipe_through :browser

    # LiveView routes with current path hook
    live_session :default do
      live "/", RsolvWeb.HomeLive, :index
      live "/signup", RsolvWeb.EarlyAccessLive, :index
    end
    
    # Blog routes
    get "/blog", RsolvWeb.BlogController, :index
    get "/blog/rss.xml", RsolvWeb.BlogController, :rss
    get "/blog/:slug", RsolvWeb.BlogController, :show
    
    # Dashboard routes
    get "/dashboard", RsolvWeb.DashboardController, :index
    
    # Page routes
    get "/thank-you", RsolvWeb.PageController, :thank_you
    get "/docs/privacy", RsolvWeb.PageController, :privacy
    get "/docs/terms", RsolvWeb.PageController, :terms
    get "/unsubscribe", RsolvWeb.PageController, :unsubscribe
    post "/unsubscribe", RsolvWeb.PageController, :process_unsubscribe
  end

  # Webhook endpoints (separate from API versioning)
  scope "/webhook", RsolvWeb do
    pipe_through :webhook
    
    post "/github", WebhookController, :github
  end

  # API v1
  scope "/api/v1", RsolvWeb, as: :api_v1 do
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
    
    # Feedback
    scope "/feedback" do
      get "/", API.FeedbackController, :index
      post "/", API.FeedbackController, :create
      get "/stats", API.FeedbackController, :stats
      get "/:id", API.FeedbackController, :show
    end

    # Security patterns
    scope "/patterns" do
      # Main pattern endpoints (access level determined by authentication)
      get "/", Api.V1.PatternController, :index
      get "/stats", Api.V1.PatternController, :stats
      
      # Pattern by language endpoint
      get "/:language", Api.V1.PatternController, :by_language
      
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
    
    # Vulnerability Validation (RFC-036)
    scope "/vulnerabilities" do
      post "/validate", Api.V1.VulnerabilityValidationController, :validate
    end
    
    # Test endpoints removed - we don't use tiers anymore
  end

  # API v2 - Enhanced format by default
  scope "/api/v2", RsolvWeb, as: :api_v2 do
    pipe_through :api

    # Security patterns with enhanced format by default
    scope "/patterns" do
      # Main pattern endpoint (returns enhanced format by default)
      get "/", Api.V1.PatternController, :index_v2
    end
  end
  
  # Prometheus metrics endpoint
  forward "/metrics", PromEx.Plug, prom_ex_module: Rsolv.PromEx
end