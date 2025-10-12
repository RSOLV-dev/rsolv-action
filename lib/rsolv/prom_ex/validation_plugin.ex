defmodule Rsolv.PromEx.ValidationPlugin do
  use PromEx.Plugin

  @impl true
  def event_metrics(_opts) do
    [
      counter("rsolv.validation.executions.total",
        event_name: [:rsolv, :validation, :complete],
        description: "Total validation executions"
      )
    ]
  end

  @impl true
  def polling_metrics(_opts), do: []

  @impl true
  def manual_metrics(_opts), do: []
end
