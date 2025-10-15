defmodule Rsolv.Security.PatternSupervisor do
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
      {Rsolv.Security.PatternServer, []},

      # Task supervisor for async operations
      {Task.Supervisor, name: Rsolv.Security.TaskSupervisor},

      # Telemetry setup
      {Rsolv.Security.PatternTelemetry, []}

      # AI review pool disabled for now (poolboy not in dependencies)
      # :poolboy.child_spec(
      #   :ai_review_pool,
      #   pool_config(),
      #   []
      # )
    ]

    # If pattern compiler is available, add it
    children =
      if Code.ensure_loaded?(Rsolv.Security.PatternCompiler) do
        [{Rsolv.Security.PatternCompiler, []} | children]
      else
        children
      end

    Supervisor.init(children, strategy: :one_for_one)
  end
end
