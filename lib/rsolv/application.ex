defmodule RSOLV.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    # Base children that always start
    base_children = [
      # Start the Telemetry supervisor
      RSOLVWeb.Telemetry,
      # Start the PromEx supervisor for Prometheus metrics
      RSOLV.PromEx,
      # Start the Ecto repository
      RsolvApi.Repo,
      # Start the PubSub system
      {Phoenix.PubSub, name: RSOLV.PubSub},
      # Start Cachex
      {Cachex, name: :rsolv_cache},
      # Start the Rate Limiter
      RSOLV.RateLimiter,
      # Start the Notifications supervisor
      RSOLV.Notifications.Supervisor,
      # Start the Pattern supervisor for security patterns
      RsolvApi.Security.PatternSupervisor,
      # Start the AST Analysis services
      RsolvApi.AST.SessionManager,
      RsolvApi.AST.PortSupervisor,
      RsolvApi.AST.ParserRegistry,
      RsolvApi.AST.AnalysisService,
      # Start the Endpoint (http/https)
      RSOLVWeb.Endpoint
      # Start a worker by calling: RSOLV.Worker.start_link(arg)
      # {RSOLV.Worker, arg}
    ]
    
    # Add cluster supervisor if clustering is configured
    cluster_children = 
      if RSOLV.Cluster.clustering_enabled?() do
        [
          {Cluster.Supervisor, [RSOLV.Cluster.topologies(), [name: RSOLV.ClusterSupervisor]]},
          RSOLV.ClusterMonitor
        ]
      else
        []
      end
    
    children = cluster_children ++ base_children

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: RSOLV.Supervisor]
    
    # Set up cluster event handlers before starting
    if RSOLV.Cluster.clustering_enabled?() do
      :net_kernel.monitor_nodes(true, node_type: :all)
    end
    
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    RSOLVWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end