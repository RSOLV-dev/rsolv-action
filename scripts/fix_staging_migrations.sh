#!/bin/bash
# Script to fix staging database migration state

# List of migrations that should be marked as already run
# based on existing tables in staging
EXISTING_MIGRATIONS=(
  "20250531"      # fun_with_flags
  "20240525000001" # customers
  "20240525000002" # credentials  
  "20240525000003" # usage_records
  "20250103010000" # feedback_tables
  "20250602000001" # fix_attempts
  "20250602000002" # trial_tracking
  "20250603000001" # issue_number_nullable
  "20250607235726" # security_patterns (already dropped)
  "20250609164136" # drop_pattern_tables
  "20250703021531" # users_auth_tables
  "20250703021557" # customers_user_reference
  "20250703021615" # api_keys
  "20250703021633" # email_subscriptions
  "20250703162754" # analytics_tables
  "20250703191713" # oban_jobs
  "20250703192155" # email_management
  "20250703195000" # early_access_signups
  "20250703214726" # drop_analytics_for_landing
  "20250703230100" # analytics_partitioned
)

echo "Marking existing migrations as complete in staging..."

for version in "${EXISTING_MIGRATIONS[@]}"; do
  echo "Marking migration $version as complete..."
  kubectl exec -n rsolv-staging staging-postgres-58fd969895-r87l7 -- psql -U rsolv -d rsolv_staging -c \
    "INSERT INTO schema_migrations (version, inserted_at) VALUES ($version, NOW()) ON CONFLICT (version) DO NOTHING;"
done

echo "Creating analytics partition function..."
kubectl exec -n rsolv-staging staging-postgres-58fd969895-r87l7 -- psql -U rsolv -d rsolv_staging -c "
CREATE OR REPLACE FUNCTION create_analytics_partition_if_not_exists(partition_date DATE)
RETURNS void AS \$\$
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
\$\$ LANGUAGE plpgsql;
"

echo "Done! Migrations should now be in sync."