#!/usr/bin/env elixir

# Check the feature flag status in the database

{:ok, _} = Application.ensure_all_started(:postgrex)
{:ok, _} = Application.ensure_all_started(:ecto_sql)

case Rsolv.Repo.start_link() do
  {:ok, _pid} -> :ok
  {:error, {:already_started, _pid}} -> :ok
  error -> IO.puts("Failed to start repo: #{inspect(error)}")
end

result = Rsolv.Repo.query!(
  "SELECT flag_name, gate_type, target, enabled FROM fun_with_flags_toggles WHERE flag_name = 'false_positive_caching'"
)

IO.puts("Database flag status:")
IO.inspect(result.rows)

case result.rows do
  [["false_positive_caching", "boolean", "", true]] ->
    IO.puts("✅ Flag is ENABLED in database")
  [["false_positive_caching", "boolean", "", false]] ->
    IO.puts("❌ Flag is DISABLED in database")
  _ ->
    IO.puts("⚠️  Unexpected flag state")
end