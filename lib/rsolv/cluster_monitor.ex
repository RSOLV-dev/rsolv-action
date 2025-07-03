defmodule Rsolv.ClusterMonitor do
  @moduledoc """
  Monitors cluster events and handles node up/down notifications.
  """
  
  use GenServer
  require Logger
  
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end
  
  @impl true
  def init(_opts) do
    # Subscribe to node events
    :net_kernel.monitor_nodes(true, node_type: :all)
    
    # Log initial cluster state
    Logger.info("Cluster monitor started. Current node: #{Node.self()}")
    Logger.info("Connected nodes: #{inspect(Node.list())}")
    
    {:ok, %{}}
  end
  
  @impl true
  def handle_info({:nodeup, node, _node_type}, state) do
    Rsolv.Cluster.on_node_connect(node)
    {:noreply, state}
  end
  
  @impl true
  def handle_info({:nodedown, node, _node_type}, state) do
    Rsolv.Cluster.on_node_disconnect(node)
    {:noreply, state}
  end
  
  @impl true
  def handle_info(msg, state) do
    Logger.debug("ClusterMonitor received unexpected message: #{inspect(msg)}")
    {:noreply, state}
  end
end