defmodule Mix.Tasks.CheckFlags do
  use Mix.Task

  @shortdoc "Check feature flag status"

  def run(_) do
    Mix.Task.run("app.start")

    IO.puts("Checking feature flags...\n")

    flags = [:admin_dashboard, :metrics_dashboard, :feedback_dashboard]

    for flag <- flags do
      # Check global flag
      global = FunWithFlags.enabled?(flag)

      # Check with custom module
      custom = Rsolv.FeatureFlags.enabled?(flag)

      IO.puts("#{flag}:")
      IO.puts("  FunWithFlags.enabled?: #{global}")
      IO.puts("  Rsolv.FeatureFlags.enabled?: #{custom}")
      IO.puts("")
    end
  end
end
