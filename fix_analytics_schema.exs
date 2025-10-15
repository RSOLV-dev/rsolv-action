# Script to properly fix analytics_events table using migrations
alias Rsolv.Repo

IO.puts("Checking current schema_migrations...")
{:ok, %{rows: migrations}} = Repo.query("SELECT version FROM schema_migrations ORDER BY version")
IO.puts("Found #{length(migrations)} migrations applied")

# Check if the partitioned table migration has been applied
partitioned_migration = "20250703230100"
has_partitioned = Enum.any?(migrations, fn [v] -> v == partitioned_migration end)

if has_partitioned do
  IO.puts("✅ Partitioned table migration already applied")
else
  IO.puts("❌ Partitioned table migration NOT applied - this is the issue!")
  IO.puts("Need to run migration: #{partitioned_migration}")
end

# Check if analytics_events table exists
{:ok, %{rows: tables}} =
  Repo.query("""
    SELECT table_name
    FROM information_schema.tables
    WHERE table_name = 'analytics_events'
  """)

if length(tables) > 0 do
  IO.puts("\n✅ Table analytics_events exists")

  # Check columns
  {:ok, %{rows: columns}} =
    Repo.query("""
      SELECT column_name
      FROM information_schema.columns
      WHERE table_name = 'analytics_events'
      ORDER BY ordinal_position
    """)

  IO.puts("Current columns: #{Enum.map(columns, fn [c] -> c end) |> Enum.join(", ")}")
else
  IO.puts("\n❌ Table analytics_events does NOT exist")
end
