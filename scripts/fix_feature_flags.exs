# Script to fix feature flag duplicates
# Run with: mix run scripts/fix_feature_flags.exs

alias Rsolv.Repo

IO.puts("Fixing feature flag duplicates...")

# Check current state
{:ok, result} = Repo.query("""
  SELECT id, flag_name, gate_type, target, enabled 
  FROM fun_with_flags_toggles 
  WHERE flag_name = 'metrics_dashboard'
  ORDER BY id
""")

IO.puts("\nCurrent gates for metrics_dashboard:")
Enum.each(result.rows, fn row ->
  IO.inspect(row)
end)

# Clean up duplicates - keep only the latest
if length(result.rows) > 0 do
  IO.puts("\nCleaning up duplicates...")
  {:ok, _} = Repo.query("""
    DELETE FROM fun_with_flags_toggles 
    WHERE flag_name = 'metrics_dashboard'
  """)
  IO.puts("Deleted all gates for metrics_dashboard")
end

# Set it cleanly
IO.puts("\nSetting flag to enabled...")
FunWithFlags.enable(:metrics_dashboard)

# Give it a moment
Process.sleep(100)

# Check final state
enabled = FunWithFlags.enabled?(:metrics_dashboard)
IO.puts("\nFinal state - metrics_dashboard enabled: #{enabled}")

# Show final gates
{:ok, final_result} = Repo.query("""
  SELECT id, flag_name, gate_type, target, enabled 
  FROM fun_with_flags_toggles 
  WHERE flag_name = 'metrics_dashboard'
""")

IO.puts("\nFinal gates:")
Enum.each(final_result.rows, fn row ->
  IO.inspect(row)
end)