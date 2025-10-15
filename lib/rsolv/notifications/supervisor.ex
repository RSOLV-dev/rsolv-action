defmodule Rsolv.Notifications.Supervisor do
  @moduledoc """
  Supervises all notification-related processes
  """

  use Supervisor

  def start_link(init_arg) do
    Supervisor.start_link(__MODULE__, init_arg, name: __MODULE__)
  end

  @impl true
  def init(_init_arg) do
    children = [
      # AlertThrottle now uses the existing cache, no need to supervise
      {Rsolv.Notifications.EngagementTracker, []}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end
