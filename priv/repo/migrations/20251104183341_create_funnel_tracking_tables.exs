defmodule Rsolv.Repo.Migrations.CreateFunnelTrackingTables do
  use Ecto.Migration

  def change do
    # Funnel events table - tracks each stage of customer journey
    create table(:funnel_events) do
      add :customer_id, references(:customers, on_delete: :delete_all)
      add :event_type, :string, null: false
      add :session_id, :string
      add :visitor_id, :string
      add :ip_address, :string
      add :user_agent, :text
      add :referrer, :string
      add :utm_source, :string
      add :utm_medium, :string
      add :utm_campaign, :string
      add :utm_term, :string
      add :utm_content, :string
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime, updated_at: false)
    end

    # Indexes for efficient queries
    create index(:funnel_events, [:event_type, :inserted_at])
    create index(:funnel_events, [:customer_id, :event_type])
    create index(:funnel_events, [:customer_id, :inserted_at])
    create index(:funnel_events, [:session_id])
    create index(:funnel_events, [:visitor_id])
    create index(:funnel_events, [:inserted_at])
    create index(:funnel_events, [:utm_source])
    create index(:funnel_events, [:utm_campaign])

    # Funnel metrics table - pre-aggregated conversion metrics
    create table(:funnel_metrics) do
      add :period_start, :date, null: false
      add :period_end, :date, null: false
      add :period_type, :string, null: false # 'day', 'week', 'month'

      # Stage 1: Website visits
      add :website_visits, :integer, default: 0
      add :unique_visitors, :integer, default: 0

      # Stage 2: Signups
      add :signups, :integer, default: 0

      # Stage 3: API key creation
      add :api_keys_created, :integer, default: 0

      # Stage 4: First API call (activation)
      add :activated_users, :integer, default: 0

      # Stage 5: Continued usage (retention)
      add :retained_users, :integer, default: 0

      # Conversion rates (calculated)
      add :visit_to_signup_rate, :decimal, precision: 5, scale: 2
      add :signup_to_api_key_rate, :decimal, precision: 5, scale: 2
      add :api_key_to_activation_rate, :decimal, precision: 5, scale: 2
      add :activation_to_retention_rate, :decimal, precision: 5, scale: 2

      # UTM tracking aggregates
      add :top_utm_sources, :map, default: %{}
      add :top_utm_campaigns, :map, default: %{}

      timestamps(type: :utc_datetime)
    end

    # Unique constraint on period
    create unique_index(:funnel_metrics, [:period_start, :period_type])
    create index(:funnel_metrics, [:period_start])
    create index(:funnel_metrics, [:period_type])

    # Customer journey table - tracks individual customer progress through funnel
    create table(:customer_journeys) do
      add :customer_id, references(:customers, on_delete: :delete_all), null: false
      add :visitor_id, :string
      add :session_id, :string

      # Timestamps for each funnel stage
      add :first_visit_at, :utc_datetime
      add :signup_at, :utc_datetime
      add :api_key_created_at, :utc_datetime
      add :first_api_call_at, :utc_datetime
      add :second_api_call_at, :utc_datetime # Retention indicator

      # Conversion timings (in seconds)
      add :visit_to_signup_seconds, :integer
      add :signup_to_api_key_seconds, :integer
      add :api_key_to_first_call_seconds, :integer
      add :first_to_second_call_seconds, :integer

      # UTM attribution (from first touch)
      add :utm_source, :string
      add :utm_medium, :string
      add :utm_campaign, :string
      add :utm_term, :string
      add :utm_content, :string

      # Flags for funnel completion
      add :completed_signup, :boolean, default: false
      add :completed_api_key, :boolean, default: false
      add :completed_activation, :boolean, default: false
      add :completed_retention, :boolean, default: false

      timestamps(type: :utc_datetime)
    end

    # One journey per customer
    create unique_index(:customer_journeys, [:customer_id])
    create index(:customer_journeys, [:visitor_id])
    create index(:customer_journeys, [:session_id])
    create index(:customer_journeys, [:first_visit_at])
    create index(:customer_journeys, [:signup_at])
    create index(:customer_journeys, [:utm_source])
    create index(:customer_journeys, [:utm_campaign])
    create index(:customer_journeys, [:completed_activation])
    create index(:customer_journeys, [:completed_retention])
  end
end
