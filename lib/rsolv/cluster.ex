defmodule Rsolv.Cluster do
  @moduledoc """
  Manages cluster configuration and monitoring for RSOLV API.
  
  This module provides utilities for:
  - Monitoring cluster state changes
  - Tracking connected nodes
  - Logging cluster events
  """
  
  require Logger
  
  @doc """
  Returns the current cluster topology configuration.
  """
  def topologies do
    Application.get_env(:rsolv, :cluster, [topologies: []])[:topologies] || []
  end
  
  @doc """
  Called when a node connects to the cluster.
  """
  def on_node_connect(node) do
    Logger.info("Node connected to cluster: #{inspect(node)}")
    Logger.info("Current cluster members: #{inspect(Node.list())}")
    
    # Synchronize critical state when a new node joins
    sync_with_node(node)
  end
  
  @doc """
  Called when a node disconnects from the cluster.
  """
  def on_node_disconnect(node) do
    Logger.warning("Node disconnected from cluster: #{inspect(node)}")
    Logger.info("Remaining cluster members: #{inspect(Node.list())}")
  end
  
  @doc """
  Returns information about the current cluster state.
  """
  def cluster_info do
    %{
      current_node: Node.self(),
      connected_nodes: Node.list(),
      cookie: Node.get_cookie(),
      alive?: Node.alive?(),
      topologies: topologies()
    }
  end
  
  @doc """
  Checks if clustering is enabled (production environment).
  """
  def clustering_enabled? do
    topologies() != []
  end
  
  # Private functions
  
  defp sync_with_node(node) do
    # Here you can add logic to synchronize any distributed state
    # For example, sync rate limiting counters, cache state, etc.
    Logger.debug("Synchronizing state with node: #{inspect(node)}")
    
    # Example: Notify other services about the new node
    Phoenix.PubSub.broadcast(
      Rsolv.PubSub,
      "cluster:events",
      {:node_joined, node, Node.self()}
    )
  end
end