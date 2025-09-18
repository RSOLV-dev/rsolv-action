defmodule Rsolv.Repo.Migrations.AddMetadataToAnalyticsEvents do
  use Ecto.Migration

  def change do
    alter table(:analytics_events) do
      add :metadata, :map, default: %{}
    end
  end
end
