# ADR-028: Production Database Migration Synchronization

**Date**: 2025-09-18
**Status**: Implemented
**Tags**: database, migrations, production, incident-response

## Context

On 2025-09-18, we discovered that the production database (`rsolv_platform_prod`) had an empty `schema_migrations` table despite having all the necessary database tables created. This caused the validation API to return 500 errors because it was missing the partitioned `analytics_events` table with required columns (`visitor_id`, `metadata`).

## Discovery

The issue was discovered when:
1. Validation API returned 500 errors with "column metadata of relation analytics_events does not exist"
2. Investigation revealed `schema_migrations` table had only 1 entry (`20250531`) despite 30+ migrations existing
3. Production had the old non-partitioned `analytics_events` table without required columns
4. Staging and local/dev databases had all migrations properly recorded

## Root Cause

The production database was migrated from separate `rsolv_landing_prod` and `rsolv_api_prod` databases into `rsolv_platform_prod`. During this consolidation, tables were created directly via SQL rather than through Ecto migrations, leaving the `schema_migrations` table empty.

## Decision

We implemented a migration synchronization process to:
1. Mark existing migrations as run in `schema_migrations` for tables that already exist
2. Drop the old non-partitioned `analytics_events` table
3. Run remaining migrations to create the partitioned table structure
4. Create analytics partitions for current and future months

## Implementation

The fix was applied using Ecto.Migrator.with_repo pattern:

```elixir
# Mark existing migrations for tables that already exist
migrations_to_mark = [
  20240525000001,  # CreateCustomers - customers table exists
  20250703021615,  # CreateApiKeys - api_keys table exists
  20250703162754,  # CreateAnalyticsTables - old analytics_events exists
  20250703214726,  # DropAnalyticsEventsForRsolvLanding
]

# Insert into schema_migrations
Enum.each(migrations_to_mark, fn version ->
  repo.query!(
    "INSERT INTO schema_migrations (version, inserted_at) VALUES ($1, NOW()) ON CONFLICT DO NOTHING",
    [version]
  )
end)

# Drop old table and run remaining migrations
repo.query!("DROP TABLE IF EXISTS analytics_events CASCADE")
Rsolv.ReleaseTasks.migrate()
Rsolv.ReleaseTasks.create_analytics_partitions(3)
```

## Consequences

### Positive
- All environments now have consistent database schemas
- Schema is properly managed through Ecto migrations
- Validation API is working correctly
- Analytics events table is properly partitioned with all required columns

### Negative
- Manual intervention was required to fix production
- Temporary service disruption during migration

## Lessons Learned

1. **NEVER modify database schema directly with SQL** - Always use Ecto migrations
2. **Database consolidations must preserve migration history** - When merging databases, ensure schema_migrations is properly populated
3. **All environments must have identical schemas** - Dev, staging, and production should be managed identically
4. **Test migrations locally before production** - Catch issues early in development

## Verification

After applying the fix:
- Production has 30+ migrations in schema_migrations matching staging
- analytics_events is a partitioned table with visitor_id and metadata columns
- Validation API returns 200 OK
- Health endpoint shows database as healthy

## Related

- RFC-049: Customer Management Consolidation (database merger)
- LESSONS-LEARNED-OUTAGE-2025-09-17.md
- Migration 20250703230100: Create partitioned analytics_events table