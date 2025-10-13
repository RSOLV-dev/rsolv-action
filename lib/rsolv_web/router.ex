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
  
  # Pipeline for admin auth callback - no CSRF protection needed for token-based auth
  pipeline :admin_auth do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_flash
    plug :put_root_layout, html: {RsolvWeb.Layouts, :root}
    plug :put_secure_browser_headers
  end

  pipeline :api do
    plug :accepts, ["json"]
  end
  
  pipeline :metrics do
    plug RsolvWeb.Plugs.PrometheusExPlug
  end
  
  pipeline :fetch_current_customer do
    plug RsolvWeb.CustomerAuth, :fetch_current_customer
  end
  
  pipeline :require_staff_customer do
    plug RsolvWeb.CustomerAuth, :require_staff_customer
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

  # Admin routes (public login via LiveView, protected admin area)
  scope "/admin", RsolvWeb.Admin do
    pipe_through :browser
    
    # LiveView login with proper session setup
    live_session :admin_login do
      live "/login", LoginLive, :index
    end
  end
  
  # Admin auth callback - uses separate pipeline without CSRF protection
  scope "/admin", RsolvWeb.Admin do
    pipe_through :admin_auth
    
    # Auth callback for session creation (token-based auth doesn't need CSRF)
    get "/auth", AuthController, :authenticate
  end
  
  # Protected admin routes
  scope "/admin", RsolvWeb.Admin do
    pipe_through [:browser, :fetch_current_customer, :require_staff_customer]
    
    get "/", DashboardController, :index  # Add index route that redirects to dashboard
    get "/dashboard", DashboardController, :index
    delete "/logout", DashboardController, :logout
    
    live "/customers", CustomerLive.Index, :index
    live "/customers/new", CustomerLive.Index, :new
    live "/customers/:id", CustomerLive.Show, :show
    live "/customers/:id/edit", CustomerLive.Index, :edit

    live "/api-keys", ApiKeyLive.Index, :index
    live "/api-keys/:id/edit", ApiKeyLive.Index, :edit
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
    
    # Pattern metadata endpoint moved to Api.V1.PatternController
    
    # Fix attempts
    resources "/fix-attempts", FixAttemptController, except: [:new, :edit]
  end
  
  scope "/api/v1", RsolvWeb.Api.V1 do
    pipe_through :api

    # Vulnerability validation endpoint (routed based on feature flag)
    post "/vulnerabilities/validate", VulnerabilityValidationRouter, :validate

    # Pattern endpoints
    get "/patterns", PatternController, :index
    get "/patterns/stats", PatternController, :stats
    get "/patterns/by-language/:language", PatternController, :by_language
    get "/patterns/v2", PatternController, :index_v2
    get "/patterns/:id/metadata", PatternController, :metadata

    # AST analysis endpoint
    post "/ast/analyze", ASTController, :analyze

    # Compatibility route for GitHub Action (v3.5.2 and earlier)
    # TODO: Remove after updating action to use /api/v1/vulnerabilities/validate
    post "/ast/validate", VulnerabilityValidationRouter, :validate

    # Audit log endpoint
    resources "/audit-logs", AuditLogController, only: [:index, :show]

    # Phase data endpoints
    post "/phases/store", PhaseController, :store
    get "/phases/retrieve", PhaseController, :retrieve

    # Test integration endpoints (RFC-060-AMENDMENT-001)
    post "/test-integration/analyze", TestIntegrationController, :analyze
    post "/test-integration/naming", TestIntegrationController, :naming
    post "/test-integration/generate", TestIntegrationController, :generate
  end
  
  scope "/api", RsolvWeb do
    pipe_through :api
    
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
  
  # Metrics endpoint (publicly accessible for Prometheus scraping)
  # NOTE: This endpoint is intentionally NOT behind a feature flag
  # to ensure continuous observability for monitoring systems
  scope "/metrics" do
    pipe_through :metrics

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
        metrics: RsolvWeb.Telemetry,
        request_logger_cookie_domain: nil
      
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
        metrics: RsolvWeb.Telemetry,
        request_logger_cookie_domain: ".rsolv.dev"
    end
    
    # FunWithFlags UI with auth (admin_dashboard now checked after auth in plug)
    scope path: "/feature-flags" do
      pipe_through [:browser, DashboardAuth]
      
      forward "/", FunWithFlags.UI.Router, namespace: "feature-flags"
    end
  end
end