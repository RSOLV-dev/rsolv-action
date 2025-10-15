defmodule Rsolv.Repo.Migrations.DropAnalyticsEventsForRsolvLanding do
  use Ecto.Migration

  def up do
    # Drop the analytics_events table if it exists to avoid conflicts
    # This allows the rsolv-landing analytics migration to run cleanly
    execute "DROP TABLE IF EXISTS analytics_events CASCADE"
  end

  def down do
    # Recreate the analytics_events table as it was before
    # This matches the structure from 20250703162754_create_analytics_tables.exs
    create table(:analytics_events) do
      add :event_name, :string, null: false
      add :properties, :map, default: %{}
      add :session_id, :string
      add :user_id, references(:users, on_delete: :nilify_all)

      timestamps(type: :utc_datetime)
    end

    create index(:analytics_events, [:event_name])
    create index(:analytics_events, [:session_id])
    create index(:analytics_events, [:user_id])
    create index(:analytics_events, [:inserted_at])
  end
end