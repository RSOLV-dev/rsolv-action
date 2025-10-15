alias Rsolv.Repo

case Repo.query(
       "ALTER TABLE analytics_events ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'"
     ) do
  {:ok, _} ->
    IO.puts("✅ Successfully added metadata column to analytics_events table")

  {:error, %Postgrex.Error{postgres: %{code: :duplicate_column}}} ->
    IO.puts("ℹ️  Metadata column already exists")

  {:error, error} ->
    IO.puts("❌ Error: #{inspect(error)}")
    System.halt(1)
end

# Also update schema_migrations to track this migration
Repo.query(
  "INSERT INTO schema_migrations (version, inserted_at) VALUES ('20250918023434', NOW()) ON CONFLICT DO NOTHING"
)

IO.puts("✅ Migration tracking updated")
