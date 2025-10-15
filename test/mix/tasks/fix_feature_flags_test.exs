defmodule Mix.Tasks.FixFeatureFlagsTest do
  use Rsolv.DataCase
  import ExUnit.CaptureIO

  alias Mix.Tasks.FixFeatureFlags

  describe "fix_feature_flags" do
    test "removes group gates that override global boolean gate" do
      # Setup - create a flag with both boolean and group gates
      # The group gate is what's causing the issue in production
      Rsolv.Repo.query!("""
      INSERT INTO fun_with_flags_toggles (flag_name, gate_type, target, enabled)
      VALUES
        ('metrics_dashboard', 'boolean', NULL, false),
        ('metrics_dashboard', 'group', 'admin', true)
      ON CONFLICT DO NOTHING
      """)

      # Run the task
      capture_io(fn ->
        FixFeatureFlags.run([])
      end)

      # Verify the flag is now enabled globally
      {:ok, result} =
        Rsolv.Repo.query("""
        SELECT enabled FROM fun_with_flags_toggles
        WHERE flag_name = 'metrics_dashboard' AND gate_type = 'boolean'
        ORDER BY id DESC
        LIMIT 1
        """)

      assert [[true]] = result.rows

      # Verify group gates were removed
      {:ok, result} =
        Rsolv.Repo.query("""
        SELECT COUNT(*) FROM fun_with_flags_toggles
        WHERE flag_name = 'metrics_dashboard' AND gate_type = 'group'
        """)

      assert [[0]] = result.rows
    end

    test "enables both admin_dashboard and metrics_dashboard flags" do
      # Ensure flags have disabled boolean gates initially
      Rsolv.Repo.query!("""
      INSERT INTO fun_with_flags_toggles (flag_name, gate_type, target, enabled)
      VALUES
        ('admin_dashboard', 'boolean', NULL, false),
        ('metrics_dashboard', 'boolean', NULL, false)
      ON CONFLICT (flag_name, gate_type, target)
      DO UPDATE SET enabled = false
      """)

      # Run the task
      capture_io(fn ->
        FixFeatureFlags.run([])
      end)

      # Verify both flags are enabled in the database
      {:ok, result} =
        Rsolv.Repo.query("""
        SELECT DISTINCT ON (flag_name) flag_name, enabled
        FROM fun_with_flags_toggles
        WHERE flag_name IN ('admin_dashboard', 'metrics_dashboard')
        AND gate_type = 'boolean'
        ORDER BY flag_name, id DESC
        """)

      assert [["admin_dashboard", true], ["metrics_dashboard", true]] = result.rows
    end
  end
end
