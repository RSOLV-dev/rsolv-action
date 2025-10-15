alias Rsolv.Repo

IO.puts("=== Checking applied migrations ===")
{:ok, %{rows: migrations}} = Repo.query("SELECT version FROM schema_migrations ORDER BY version")
Enum.each(migrations, fn [v] -> IO.puts("  #{v}") end)

IO.puts("\n=== Checking analytics_events table ===")

case Repo.query("SELECT 1 FROM information_schema.tables WHERE table_name = 'analytics_events'") do
  {:ok, %{rows: []}} ->
    IO.puts("❌ Table analytics_events does NOT exist")

  {:ok, %{rows: _}} ->
    IO.puts("✅ Table analytics_events exists")

    # Check columns
    {:ok, %{rows: columns}} =
      Repo.query("""
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_name = 'analytics_events'
        ORDER BY ordinal_position
      """)

    IO.puts("\nColumns:")

    Enum.each(columns, fn [name, type] ->
      IO.puts("  #{name}: #{type}")
    end)
end
