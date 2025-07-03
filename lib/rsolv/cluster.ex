defmodule Rsolv.Cluster do
  @moduledoc """
  BEAM clustering support for RSOLV Landing.
  
  This module handles automatic cluster formation in Kubernetes environments,
  enabling distributed cache invalidation and state sharing across pods.
  """
  
  use GenServer
  require Logger
  
  @doc """
  Starts the cluster manager
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end
  
  @impl true
  def init(_opts) do
    # Start clustering based on environment
    if clustering_enabled?() do
      Logger.info("Starting BEAM clustering...")
      setup_cluster()
    else
      Logger.info("BEAM clustering disabled")
    end
    
    {:ok, %{}}
  end
  
  @doc """
  Sets up the cluster based on the deployment environment
  """
  def setup_cluster do
    case Application.get_env(:rsolv, :cluster_strategy, :none) do
      :kubernetes -> setup_kubernetes_cluster()
      :dns -> setup_dns_cluster()
      :none -> :ok
      strategy -> Logger.warning("Unknown cluster strategy: #{inspect(strategy)}")
    end
  end
  
  @doc """
  Sets up Kubernetes-based clustering using headless service
  """
  def setup_kubernetes_cluster do
    # Use libcluster for Kubernetes service discovery
    service_name = System.get_env("CLUSTER_SERVICE_NAME") || "rsolv-landing-headless"
    namespace = System.get_env("POD_NAMESPACE") || "default"
    
    topologies = [
      k8s_dns: [
        strategy: Cluster.Strategy.Kubernetes.DNS,
        config: [
          service: service_name,
          namespace: namespace,
          application_name: "rsolv_landing",
          polling_interval: 5_000,
          mode: :ip
        ]
      ]
    ]
    
    # Start the cluster supervisor
    children = [
      {Cluster.Supervisor, [topologies, [name: Rsolv.ClusterSupervisor]]}
    ]
    
    Supervisor.start_link(children, strategy: :one_for_one)
    
    Logger.info("Kubernetes clustering configured with headless service")
  end
  
  @doc """
  Sets up DNS-based clustering (for non-Kubernetes environments)
  """
  def setup_dns_cluster do
    query = Application.get_env(:rsolv, :dns_cluster_query)
    
    if query do
      topologies = [
        dns: [
          strategy: Cluster.Strategy.DNSPoll,
          config: [
            polling_interval: 5_000,
            query: query,
            node_basename: "rsolv_landing"
          ]
        ]
      ]
      
      children = [
        {Cluster.Supervisor, [topologies, [name: Rsolv.ClusterSupervisor]]}
      ]
      
      Supervisor.start_link(children, strategy: :one_for_one)
      
      Logger.info("DNS clustering configured with query: #{query}")
    else
      Logger.info("DNS clustering not configured (no query specified)")
    end
  end
  
  @doc """
  Checks if clustering is enabled
  """
  def clustering_enabled? do
    Application.get_env(:rsolv, :enable_clustering, false)
  end
  
  @doc """
  Returns the current cluster members
  """
  def members do
    [Node.self() | Node.list()]
  end
  
  @doc """
  Broadcasts a message to all nodes in the cluster
  """
  def broadcast(message) do
    for node <- members() do
      :rpc.cast(node, __MODULE__, :handle_broadcast, [message])
    end
  end
  
  @doc """
  Handles incoming broadcast messages
  """
  def handle_broadcast(message) do
    Logger.debug("Received cluster broadcast: #{inspect(message)}")
    
    case message do
      {:invalidate_feature_flags_cache} ->
        # Clear the FunWithFlags cache on this node
        clear_local_cache()
        
      _ ->
        Logger.debug("Unknown broadcast message: #{inspect(message)}")
    end
  end
  
  defp clear_local_cache do
    # This will clear the ETS cache used by FunWithFlags
    try do
      :ets.delete_all_objects(:fun_with_flags_cache)
      Logger.info("Feature flags cache cleared")
    rescue
      error ->
        Logger.error("Failed to clear cache: #{inspect(error)}")
    end
  end
end