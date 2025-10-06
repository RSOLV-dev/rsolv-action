defmodule Rsolv.Repo.Migrations.FixAnalyticsPartitionConcurrency do
  use Ecto.Migration

  def up do
    # Update the function to use advisory locks to prevent race conditions
    execute """
    CREATE OR REPLACE FUNCTION create_analytics_partition_if_not_exists(partition_date DATE)
    RETURNS void AS $$
    DECLARE
      partition_name TEXT;
      start_date DATE;
      end_date DATE;
      lock_id INTEGER;
    BEGIN
      partition_name := 'analytics_events_' || to_char(partition_date, 'YYYY_MM');
      start_date := date_trunc('month', partition_date);
      end_date := start_date + interval '1 month';

      -- Use advisory lock to prevent concurrent partition creation
      -- Lock ID based on partition name hash
      lock_id := hashtext(partition_name);

      -- Try to get an exclusive lock (blocks until available)
      PERFORM pg_advisory_xact_lock(lock_id);

      -- Double-check after getting lock
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

      -- Lock is automatically released at end of transaction
    END;
    $$ LANGUAGE plpgsql;
    """
  end

  def down do
    # Revert to the original function without advisory locks
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
    """
  end
end
