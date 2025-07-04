defmodule Rsolv.Repo.Migrations.CreateAnalyticsEventsPartitioned do
  use Ecto.Migration

  def change do
    # Create the parent partitioned table
    execute """
    CREATE TABLE analytics_events (
      id BIGSERIAL,
      event_type VARCHAR(50) NOT NULL,
      visitor_id VARCHAR(255),
      session_id VARCHAR(255),
      page_path VARCHAR(500),
      referrer VARCHAR(500),
      user_agent TEXT,
      ip_address VARCHAR(255),
      utm_source VARCHAR(100),
      utm_medium VARCHAR(100),
      utm_campaign VARCHAR(100),
      utm_term VARCHAR(100),
      utm_content VARCHAR(100),
      metadata JSONB DEFAULT '{}',
      inserted_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
      PRIMARY KEY (id, inserted_at)
    ) PARTITION BY RANGE (inserted_at);
    """, """
    DROP TABLE IF EXISTS analytics_events CASCADE;
    """

    # Create indexes on the parent table (will be inherited by partitions)
    create index(:analytics_events, [:event_type, :inserted_at])
    create index(:analytics_events, [:visitor_id, :inserted_at])
    create index(:analytics_events, [:inserted_at])
    create index(:analytics_events, [:page_path, :inserted_at])
    
    # Create partitions for current and next month
    current_year = Date.utc_today().year
    current_month = Date.utc_today().month
    
    # Current month partition
    execute """
    CREATE TABLE analytics_events_#{current_year}_#{String.pad_leading(to_string(current_month), 2, "0")}
    PARTITION OF analytics_events
    FOR VALUES FROM ('#{current_year}-#{String.pad_leading(to_string(current_month), 2, "0")}-01')
    TO ('#{current_year}-#{String.pad_leading(to_string(current_month + 1), 2, "0")}-01');
    """

    # Next month partition
    next_date = Date.utc_today() |> Date.add(32) |> Date.beginning_of_month()
    next_year = next_date.year
    next_month = next_date.month
    end_date = next_date |> Date.add(31) |> Date.beginning_of_month()
    
    execute """
    CREATE TABLE analytics_events_#{next_year}_#{String.pad_leading(to_string(next_month), 2, "0")}
    PARTITION OF analytics_events
    FOR VALUES FROM ('#{next_year}-#{String.pad_leading(to_string(next_month), 2, "0")}-01')
    TO ('#{end_date.year}-#{String.pad_leading(to_string(end_date.month), 2, "0")}-01');
    """

    # Create a function to automatically create new partitions
    execute """
    CREATE OR REPLACE FUNCTION create_analytics_partition_if_not_exists(partition_date DATE)
    RETURNS void AS $$
    DECLARE
      partition_name TEXT;
      start_date DATE;
      end_date DATE;
    BEGIN
      partition_name := 'analytics_events_' || to_char(partition_date, 'YYYY_MM');
      start_date := date_trunc('month', partition_date);
      end_date := start_date + interval '1 month';
      
      IF NOT EXISTS (
        SELECT 1 FROM pg_tables 
        WHERE tablename = partition_name
      ) THEN
        EXECUTE format(
          'CREATE TABLE %I PARTITION OF analytics_events FOR VALUES FROM (%L) TO (%L)',
          partition_name,
          start_date,
          end_date
        );
      END IF;
    END;
    $$ LANGUAGE plpgsql;
    """, """
    DROP FUNCTION IF EXISTS create_analytics_partition_if_not_exists(DATE);
    """

    # Create a materialized view for daily stats
    execute """
    CREATE MATERIALIZED VIEW analytics_daily_stats AS
    SELECT 
      DATE(inserted_at) as date,
      event_type,
      COUNT(*) as event_count,
      COUNT(DISTINCT visitor_id) as unique_visitors,
      COUNT(DISTINCT session_id) as unique_sessions
    FROM analytics_events
    GROUP BY DATE(inserted_at), event_type
    WITH DATA;
    """, """
    DROP MATERIALIZED VIEW IF EXISTS analytics_daily_stats;
    """

    # Create index on the materialized view
    execute """
    CREATE INDEX idx_analytics_daily_stats_date ON analytics_daily_stats(date DESC);
    """
  end
end