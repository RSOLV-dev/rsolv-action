defmodule RSOLVWeb.Router do
  use RSOLVWeb, :router

  pipeline :api do
    plug :accepts, ["json"]
    plug :put_secure_browser_headers
  end

  # API v1 routes
  scope "/api/v1", RSOLVWeb do
    pipe_through :api

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
  end

  # Webhook endpoint for GitHub
  scope "/webhook", RSOLVWeb do
    post "/github", WebhookController, :github
  end

  # Health check
  scope "/", RSOLVWeb do
    get "/health", HealthController, :check
  end
end