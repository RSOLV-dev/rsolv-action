defmodule Rsolv.Repo.Migrations.DropAnalyticsEventsForRsolvLanding do
  use Ecto.Migration

  def change do
    # Drop the analytics_events table if it exists to avoid conflicts
    # This allows the rsolv-landing analytics migration to run cleanly
    execute "DROP TABLE IF EXISTS analytics_events CASCADE", 
            "SELECT 1" # No-op on rollback since we want to recreate later
  end
end