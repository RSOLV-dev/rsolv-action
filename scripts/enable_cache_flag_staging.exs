#!/usr/bin/env elixir

# Script to enable the false positive caching feature flag in staging

IO.puts("Enabling false positive caching feature flag...")

# Since we're running in eval mode, we need to start the repo
{:ok, _} = Application.ensure_all_started(:postgrex)
{:ok, _} = Application.ensure_all_started(:ecto_sql)

# Manually start the repo if needed
case Rsolv.Repo.start_link() do
  {:ok, _pid} -> 
    IO.puts("Started Repo")
  {:error, {:already_started, _pid}} -> 
    IO.puts("Repo already started")
  error ->
    IO.puts("Failed to start repo: #{inspect(error)}")
end

# Update the flag directly in the database
case Rsolv.Repo.query(
  "UPDATE fun_with_flags_toggles SET enabled = true WHERE flag_name = 'false_positive_caching' AND gate_type = 'boolean' RETURNING enabled"
) do
  {:ok, %{num_rows: 1, rows: [[true]]}} ->
    IO.puts("✅ Successfully enabled false_positive_caching feature flag")
    
  {:ok, %{num_rows: 0}} ->
    # Flag doesn't exist, create it
    case Rsolv.Repo.query(
      "INSERT INTO fun_with_flags_toggles (flag_name, gate_type, target, enabled) VALUES ('false_positive_caching', 'boolean', '', true)"
    ) do
      {:ok, _} ->
        IO.puts("✅ Created and enabled false_positive_caching feature flag")
      error ->
        IO.puts("❌ Failed to create flag: #{inspect(error)}")
    end
    
  error ->
    IO.puts("❌ Failed to update flag: #{inspect(error)}")
end

# Verify the flag is enabled
case Rsolv.Repo.query(
  "SELECT enabled FROM fun_with_flags_toggles WHERE flag_name = 'false_positive_caching'"
) do
  {:ok, %{rows: [[true]]}} ->
    IO.puts("✅ Verified: Feature flag is ENABLED")
  {:ok, %{rows: [[false]]}} ->
    IO.puts("⚠️  Warning: Feature flag is still DISABLED")
  _ ->
    IO.puts("❌ Could not verify flag status")
end