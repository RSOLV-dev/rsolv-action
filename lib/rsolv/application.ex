defmodule Rsolv.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    # Ensure JSON encoders are loaded
    Code.ensure_loaded!(Rsolv.JsonEncoders)
    # Base children that always start
    base_children = [
      # Start the Telemetry supervisor
      RsolvWeb.Telemetry,
      # Start the PromEx supervisor for Prometheus metrics
      Rsolv.PromEx,
      # Start the Ecto repository
      Rsolv.Repo,
      # Start the PubSub system
      {Phoenix.PubSub, name: Rsolv.PubSub},
      # Start Cachex
      {Cachex, name: :rsolv_cache},
      # Start the Rate Limiter
      Rsolv.RateLimiter,
      # Start the Notifications supervisor
      Rsolv.Notifications.Supervisor,
      # Start the Analytics service
      Rsolv.Analytics,
      # Start the Pattern supervisor for security patterns
      Rsolv.Security.PatternSupervisor,
      # Start the AST Analysis services
      Rsolv.AST.SessionManager,
      Rsolv.AST.PortSupervisor,
      Rsolv.AST.ParserRegistry,
      Rsolv.AST.AnalysisService,
      # Start the Validation Cache
      Rsolv.Cache.ValidationCache,
      # Start the Endpoint (http/https)
      RsolvWeb.Endpoint
      # Start a worker by calling: RSOLV.Worker.start_link(arg)
      # {RSOLV.Worker, arg}
    ]
    
    # Add FunWithFlags only if not already started (handles test environment)
    base_children = if Process.whereis(FunWithFlags.Supervisor) do
      base_children
    else
      # Insert FunWithFlags after PubSub
      {before_pubsub, [pubsub | after_pubsub]} = Enum.split_while(base_children, &(&1 != {Phoenix.PubSub, name: Rsolv.PubSub}))
      before_pubsub ++ [pubsub, FunWithFlags.Supervisor] ++ after_pubsub
    end
    
    # Add cluster supervisor if clustering is configured
    cluster_children = 
      if Rsolv.Cluster.clustering_enabled?() do
        [
          {Cluster.Supervisor, [Rsolv.Cluster.topologies(), [name: Rsolv.ClusterSupervisor]]},
          Rsolv.ClusterMonitor
        ]
      else
        []
      end
    
    children = cluster_children ++ base_children

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Rsolv.Supervisor]
    
    # Set up cluster event handlers before starting
    if Rsolv.Cluster.clustering_enabled?() do
      :net_kernel.monitor_nodes(true, node_type: :all)
    end
    
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    RsolvWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end