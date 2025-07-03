defmodule Rsolv.AST.PortWrapper do
  @moduledoc """
  Wrapper supervisor for individual PortWorker processes.
  Handles restart logic and tracking.
  """
  
  use Supervisor
  
  alias Rsolv.AST.PortWorker
  
  require Logger
  
  def start_link(config) do
    Supervisor.start_link(__MODULE__, config)
  end
  
  @impl true
  def init(config) do
    children = [
      {PortWorker, config}
    ]
    
    # Configure restart strategy based on config
    max_restarts = config[:max_restarts] || 3
    max_seconds = config[:restart_window] || 60
    
    opts = [
      strategy: :one_for_one,
      max_restarts: max_restarts,
      max_seconds: max_seconds
    ]
    
    Supervisor.init(children, opts)
  end
  
  @doc """
  Gets the PortWorker PID from this wrapper.
  """
  def get_worker_pid(wrapper_pid) do
    children = Supervisor.which_children(wrapper_pid)
    
    case Enum.find(children, fn {id, _pid, _type, _modules} -> id == PortWorker end) do
      {PortWorker, pid, :worker, [PortWorker]} when is_pid(pid) -> pid
      _ -> nil
    end
  end
  
  @doc """
  Checks if the worker has been restarted.
  """
  def get_restart_count(wrapper_pid) do
    # Use Supervisor.count_children to get restart info
    %{active: _active, specs: _specs, supervisors: _supervisors, workers: workers} = 
      Supervisor.count_children(wrapper_pid)
    
    # For now, we'll track restarts in ETS
    # This is a simplified approach
    workers
  end
end