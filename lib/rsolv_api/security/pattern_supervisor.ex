defmodule RsolvApi.Security.PatternSupervisor do
  @moduledoc """
  Supervisor for the pattern management system.
  
  This supervisor manages:
  - PatternServer (GenServer with ETS storage)
  - PatternCompiler (for AST rule compilation)
  - PatternMetrics (telemetry and stats collection)
  - AIReviewPool (pooled connections for AI reviews)
  """
  
  use Supervisor
  
  def start_link(init_arg) do
    Supervisor.start_link(__MODULE__, init_arg, name: __MODULE__)
  end
  
  @impl true
  def init(_init_arg) do
    children = [
      # Pattern server for managing and caching patterns
      {RsolvApi.Security.PatternServer, []},
      
      # Task supervisor for async operations
      {Task.Supervisor, name: RsolvApi.Security.TaskSupervisor},
      
      # Telemetry setup
      {RsolvApi.Security.PatternTelemetry, []},
      
      # AI review pool using poolboy
      :poolboy.child_spec(
        :ai_review_pool,
        pool_config(),
        []
      )
    ]
    
    # If pattern compiler is available, add it
    children = if Code.ensure_loaded?(RsolvApi.Security.PatternCompiler) do
      [{RsolvApi.Security.PatternCompiler, []} | children]
    else
      children
    end
    
    Supervisor.init(children, strategy: :one_for_one)
  end
  
  defp pool_config do
    [
      name: {:local, :ai_review_pool},
      worker_module: RsolvApi.Security.AIReviewWorker,
      size: 5,
      max_overflow: 10,
      strategy: :fifo
    ]
  end
end