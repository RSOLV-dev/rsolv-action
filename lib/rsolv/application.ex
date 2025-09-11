defmodule Rsolv.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application
  require Logger

  @impl true
  def start(_type, _args) do
    # Ensure Hackney is started (required for HTTP requests)
    {:ok, _} = Application.ensure_all_started(:hackney)
    
    # Create ETS table for customer sessions
    :ets.new(:customer_sessions, [:set, :public, :named_table])
    
    # Ensure required directories exist
    create_required_directories()

    # Set up Prometheus metrics collection
    RsolvWeb.Plugs.PrometheusExPlug.setup()
    
    # Build the list of children dynamically based on available modules
    children = [
      # Start the Ecto repository
      Rsolv.Repo,
      # Start the Telemetry supervisor
      RsolvWeb.Telemetry,
      # Start the PubSub system
      {Phoenix.PubSub, name: Rsolv.PubSub},
      # Start Oban
      {Oban, Application.fetch_env!(:rsolv, Oban)},
      # Start the cluster manager (for distributed cache invalidation)
      Rsolv.Cluster,
      # Start security services
      Rsolv.Security.PatternServer,
      # Start rate limiting
      Rsolv.RateLimiter,
      # Start cache services
      Rsolv.Cache.ValidationCache,
      # Start telemetry reporter for validation metrics
      Rsolv.Telemetry.ValidationReporter,
      # Start AST services
      Rsolv.AST.ASTCache,
      Rsolv.AST.AuditLogger,
      Rsolv.AST.SessionManager,
      Rsolv.AST.ParserRegistry,
      Rsolv.AST.PortSupervisor,
      {Rsolv.AST.ParserPool, Application.get_env(:rsolv, Rsolv.AST.ParserPool, [])},
      Rsolv.AST.AnalysisService,
      # Note: FunWithFlags.Supervisor is started automatically by the library
      # Start a worker by calling: Rsolv.Worker.start_link(arg)
      # {Rsolv.Worker, arg},
      # Start to serve requests, typically the last entry
      RsolvWeb.Endpoint
    ]
    
    # Add DNSCluster only if it exists (it's a Phoenix 1.7.x feature)
    children = if Code.ensure_loaded?(DNSCluster) do
      dns_child = {DNSCluster, query: Application.get_env(:rsolv, :dns_cluster_query) || :ignore}
      [dns_child | children]
    else
      children
    end

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Rsolv.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    RsolvWeb.Endpoint.config_change(changed, removed)
    :ok
  end

  # Create any required directories for the application
  defp create_required_directories do
    # All file-based storage has been migrated to database
    # No directories need to be created anymore
    :ok
  end
end
