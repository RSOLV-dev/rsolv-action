defmodule Mix.Tasks.FixFeatureFlags do
  use Mix.Task

  @shortdoc "Fix feature flag settings"

  def run(_) do
    Mix.Task.run("app.start")

    IO.puts("Checking feature flag gates...\n")

    # Check all gates for metrics_dashboard
    query = """
    SELECT flag_name, gate_type, target, enabled 
    FROM fun_with_flags_toggles 
    WHERE flag_name = 'metrics_dashboard' 
    ORDER BY gate_type, target
    """

    {:ok, result} = Rsolv.Repo.query(query)

    IO.puts("Current metrics_dashboard gates:")

    for row <- result.rows do
      [_flag, gate_type, target, enabled] = row
      IO.puts("  #{gate_type} - #{target || "global"} - #{enabled}")
    end

    # Check if there's a group gate that's overriding
    has_group_gate = Enum.any?(result.rows, fn [_, gate_type, _, _] -> gate_type == "group" end)

    if has_group_gate do
      IO.puts("\nFound group gate(s) that may be overriding the global boolean gate.")
      IO.puts("Removing group gates to allow global flag to work...")

      {:ok, _} =
        Rsolv.Repo.query("""
        DELETE FROM fun_with_flags_toggles 
        WHERE flag_name = 'metrics_dashboard' AND gate_type = 'group'
        """)

      IO.puts("Group gates removed.")
    end

    # Ensure the boolean gate exists and is enabled
    IO.puts("\nEnabling global boolean gate...")

    {:ok, _} =
      Rsolv.Repo.query("""
      INSERT INTO fun_with_flags_toggles (flag_name, gate_type, target, enabled)
      VALUES ('metrics_dashboard', 'boolean', NULL, true)
      ON CONFLICT (flag_name, gate_type, target) 
      DO UPDATE SET enabled = true
      """)

    # Also enable admin_dashboard
    {:ok, _} =
      Rsolv.Repo.query("""
      INSERT INTO fun_with_flags_toggles (flag_name, gate_type, target, enabled)
      VALUES ('admin_dashboard', 'boolean', NULL, true)
      ON CONFLICT (flag_name, gate_type, target) 
      DO UPDATE SET enabled = true
      """)

    # Verify the fix
    IO.puts("\nVerifying flags are enabled...")

    for flag <- [:admin_dashboard, :metrics_dashboard] do
      enabled = FunWithFlags.enabled?(flag)
      IO.puts("  #{flag}: #{enabled}")
    end

    IO.puts("\nDone!")
  end
end
