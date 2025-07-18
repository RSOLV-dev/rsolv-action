defmodule RsolvWeb.Router do
  use RsolvWeb, :router
  import Phoenix.LiveView.Router
  alias RsolvWeb.Plugs.{FeatureFlagPlug, DashboardAuth}

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
  end
  
  pipeline :metrics do
    plug RsolvWeb.Plugs.PrometheusExPlug
  end
  
  # Feature flag pipelines
  pipeline :require_admin_dashboard do
    plug FeatureFlagPlug, feature: :admin_dashboard, fallback_url: "/", 
      message: "Admin dashboard is currently unavailable."
  end
  
  pipeline :require_metrics_dashboard do
    plug FeatureFlagPlug, feature: :metrics_dashboard, fallback_url: "/", 
      message: "Metrics dashboard is currently unavailable."
  end
  
  pipeline :require_feedback_dashboard do
    plug FeatureFlagPlug, feature: :feedback_dashboard, fallback_url: "/", 
      message: "Feedback dashboard is currently unavailable."
  end

  scope "/", RsolvWeb do
    pipe_through :browser

    # LiveView routes with current path hook
    live_session :default, on_mount: [{RsolvWeb.LiveHooks, :assign_current_path}] do
      live "/", HomeLive, :index
      live "/signup", EarlyAccessLive, :index
      live "/contact", ContactLive, :index
    end
    
    # Regular routes
    post "/early-access", PageController, :submit_early_access
    get "/health", PageController, :health
    get "/thank-you", PageController, :thank_you
    get "/early-access-feedback", PageController, :early_access_feedback
    get "/feedback", PageController, :feedback
    get "/unsubscribe", PageController, :unsubscribe
    post "/unsubscribe", PageController, :process_unsubscribe
    
    # Analytics tracking endpoint (moved to API section for CSRF-free access)
    
    # Documentation pages
    get "/docs/terms", PageController, :terms
    get "/docs/privacy", PageController, :privacy
    
    # Blog routes (protected by feature flag in controller)
    get "/blog", BlogController, :index
    get "/blog/rss.xml", BlogController, :rss
    get "/blog/:slug", BlogController, :show
    
    # SEO routes
    get "/sitemap.xml", SitemapController, :index
  end
  
  # Dashboard routes with authentication and feature flags
  scope "/dashboard", RsolvWeb do
    pipe_through [:browser, DashboardAuth, :require_admin_dashboard]
    
    get "/", DashboardController, :index
    get "/report", ReportController, :download
  end
  
  # Analytics dashboard with metrics feature flag
  scope "/dashboard", RsolvWeb do
    pipe_through [:browser, DashboardAuth, :require_admin_dashboard, :require_metrics_dashboard]
    
    live_session :dashboard_analytics, on_mount: [{RsolvWeb.LiveHooks, :assign_current_path}] do
      live "/analytics", DashboardLive, :index
      live "/signup-metrics", SignupMetricsLive, :index
    end
  end
  
  # Feedback dashboard with feedback feature flag
  scope "/dashboard", RsolvWeb do
    pipe_through [:browser, DashboardAuth, :require_admin_dashboard, :require_feedback_dashboard]
    
    live_session :dashboard_feedback, on_mount: [{RsolvWeb.LiveHooks, :assign_current_path}] do
      live "/feedback", FeedbackDashLive, :index
    end
  end

  # API Routes
  scope "/api", RsolvWeb.API do
    pipe_through :api
    
    # Feedback endpoints
    get "/feedback/stats", FeedbackController, :stats
    resources "/feedback", FeedbackController, except: [:delete, :new, :edit]
  end
  
  # API v1 Routes (from consolidated RSOLV-api)
  scope "/api/v1", RsolvWeb do
    pipe_through :api
    
    # Credential exchange endpoints
    post "/credentials/exchange", CredentialController, :exchange
    post "/credentials/refresh", CredentialController, :refresh
    post "/usage/report", CredentialController, :report_usage
    
    # Pattern metadata endpoint (uses non-versioned controller)
    get "/patterns/:id/metadata", PatternController, :metadata
    
    # Fix attempts
    resources "/fix-attempts", FixAttemptController, except: [:new, :edit]
  end
  
  scope "/api/v1", RsolvWeb.Api.V1 do
    pipe_through :api
    
    # Vulnerability validation endpoint
    post "/vulnerabilities/validate", VulnerabilityValidationController, :validate
    
    # Pattern endpoints
    get "/patterns", PatternController, :index
    get "/patterns/stats", PatternController, :stats
    get "/patterns/by-language/:language", PatternController, :by_language
    get "/patterns/v2", PatternController, :index_v2
    
    # AST analysis endpoint
    post "/ast/analyze", ASTController, :analyze
    
    # Audit log endpoint
    resources "/audit-logs", AuditLogController, only: [:index, :show]
  end
  
  # Legacy pattern endpoints (non-versioned API)
  scope "/api", RsolvWeb do
    pipe_through :api
    
    # Pattern endpoints
    get "/patterns", PatternController, :index
    get "/patterns/public/:language", PatternController, :public
    get "/patterns/protected/:language", PatternController, :protected
    get "/patterns/ai/:language", PatternController, :ai
    get "/patterns/enterprise/:language", PatternController, :enterprise
    get "/patterns/by-language/:language", PatternController, :by_language
    get "/patterns/all/public", PatternController, :all_public
    get "/patterns/all/protected", PatternController, :all_protected
    get "/patterns/all/ai", PatternController, :all_ai
    get "/patterns/all/enterprise", PatternController, :all_enterprise
    
    # Health check
    get "/health", HealthController, :index
    
    # Analytics tracking endpoint (CSRF-free for client-side JavaScript)
    post "/track", TrackController, :track
    
    # Webhooks
    post "/webhooks/github", WebhookController, :github
    
    
    # Education resources
    get "/education/resources", EducationController, :index
    get "/education/resources/:id", EducationController, :show
    
    # Feature flags
    get "/feature-flags", FeatureFlagController, :index
    get "/feature-flags/:flag", FeatureFlagController, :show
  end
  
  # Define metrics feature flag pipeline
  pipeline :require_metrics_feature do
    plug RsolvWeb.Plugs.FeatureFlagPlug, feature: :metrics_dashboard
  end

  # Metrics endpoint (requires metrics feature flag)
  scope "/metrics" do
    pipe_through [:metrics, :require_metrics_feature]
    
    get "/", RsolvWeb.MetricsController, :index
  end

  # Import LiveDashboard Router once
  import Phoenix.LiveDashboard.Router
  
  # Enable LiveDashboard and feature flags routes
  if Application.compile_env(:rsolv, :dev_routes) do
    # If you want to use the LiveDashboard in production, you should put
    # it behind authentication and allow only admins to access it.
    # If your application does not have an admins-only section yet,
    # you can use Plug.BasicAuth to set up some basic authentication
    # as long as you are also using SSL (which you should anyway).

    scope "/dev" do
      pipe_through :browser

      live_dashboard "/dashboard", 
        metrics: RsolvWeb.Telemetry
      
      # FunWithFlags UI in development
      forward "/feature-flags", FunWithFlags.UI.Router, namespace: "dev-feature-flags"
      
      # Add Bamboo email preview in development
      if Application.compile_env(:rsolv, [:bamboo_preview, :enabled], false) do
        forward "/sent_emails", Bamboo.SentEmailViewerPlug
      end
    end
  else
    # Production routes with authentication
    scope "/live", RsolvWeb do
      pipe_through [:browser, DashboardAuth, :require_admin_dashboard]
      
      live_dashboard "/dashboard", 
        metrics: RsolvWeb.Telemetry
    end
    
    # FunWithFlags UI with auth (admin_dashboard now checked after auth in plug)
    scope path: "/feature-flags" do
      pipe_through [:browser, DashboardAuth]
      
      forward "/", FunWithFlags.UI.Router, namespace: "feature-flags"
    end
  end
end