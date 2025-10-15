# Fix the schema_migrations table to mark old migrations as already run
alias Rsolv.Repo

# First, check what's already marked as migrated
{:ok, %{rows: existing}} = Repo.query("SELECT version FROM schema_migrations")
existing_versions = Enum.map(existing, fn [v] -> v end)

IO.puts("Currently marked as migrated: #{inspect(existing_versions)}")

# Migrations that should be marked as already run (since tables exist)
already_run = [
  # CreateCustomers - table exists
  "20240525000001",
  # CreateApiKeys - table exists
  "20240525160000",
  # CreateAnalyticsTables - was run before
  "20250703162754",
  # DropAnalyticsEventsForRsolvLanding - was run
  "20250703214726"
]

# Mark them as run if not already marked
Enum.each(already_run, fn version ->
  unless version in existing_versions do
    IO.puts("Marking migration #{version} as already run...")

    Repo.query!(
      """
        INSERT INTO schema_migrations (version, inserted_at)
        VALUES ($1, NOW())
        ON CONFLICT (version) DO NOTHING
      """,
      [version]
    )
  end
end)

# Now run the partitioned analytics table migration specifically
IO.puts("\nNow running the partitioned analytics table migration...")

# The migration we need to run
partitioned_migration_version = "20250703230100"

unless partitioned_migration_version in existing_versions do
  # Drop the existing empty analytics_events table if it exists
  IO.puts("Dropping existing analytics_events table if it exists...")
  Repo.query("DROP TABLE IF EXISTS analytics_events CASCADE")

  # Now we can run the migration that creates the partitioned table
  IO.puts("Migration ready to run: #{partitioned_migration_version}")

  IO.puts(
    "Run: kubectl exec -n rsolv-production deploy/rsolv-platform -- /app/bin/rsolv eval 'Rsolv.ReleaseTasks.migrate()'"
  )
else
  IO.puts("Partitioned migration already marked as run")
end

IO.puts("\nDone!")
