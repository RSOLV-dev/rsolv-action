defmodule Rsolv.Repo.Migrations.CreateAnalyticsTables do
  use Ecto.Migration

  def change do
    # Analytics Page Views table
    create table(:analytics_page_views) do
      add :path, :string, null: false
      add :user_ip, :string
      add :utm_source, :string
      add :utm_medium, :string
      add :utm_campaign, :string
      add :utm_term, :string
      add :utm_content, :string
      add :session_id, :string
      add :user_agent, :text
      add :referrer, :text
      add :user_id, references(:users, on_delete: :nilify_all)
      
      timestamps(type: :utc_datetime)
    end
    
    create index(:analytics_page_views, [:path])
    create index(:analytics_page_views, [:utm_source])
    create index(:analytics_page_views, [:utm_campaign])
    create index(:analytics_page_views, [:session_id])
    create index(:analytics_page_views, [:user_id])
    create index(:analytics_page_views, [:inserted_at])
    
    # Analytics Events table
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
    
    # Analytics Conversions table
    create table(:analytics_conversions) do
      add :event_name, :string, null: false
      add :properties, :map, default: %{}
      add :session_id, :string
      add :value, :decimal, precision: 10, scale: 2
      add :user_id, references(:users, on_delete: :nilify_all)
      
      timestamps(type: :utc_datetime)
    end
    
    create index(:analytics_conversions, [:event_name])
    create index(:analytics_conversions, [:session_id])
    create index(:analytics_conversions, [:user_id])
    create index(:analytics_conversions, [:inserted_at])
  end
end
