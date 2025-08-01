# RSOLV Platform Deployment Addendum

This document supplements the main DEPLOYMENT.md in RSOLV-infrastructure with platform-specific details discovered during deployment.

## 🚨 Critical Deployment Requirements

### 1. Database Migrations MUST Run After Deployment

**Issue**: Migrations are NOT automatically run during deployment. The application will fail with database errors if migrations are not applied.

**Solution**: Use the provided deployment script or run migrations manually:

```bash
# Option 1: Use the deployment script (RECOMMENDED)
./scripts/deploy.sh staging  # or production

# Option 2: Run migrations manually after deployment
kubectl exec -n rsolv-staging deployment/staging-rsolv-platform -- \
  /app/bin/rsolv eval "Rsolv.Release.migrate()"
```

### 2. Analytics Partition Requirements

**Issue**: The analytics_events table uses PostgreSQL partitioning by month. If a partition doesn't exist for the current month, all page views will fail with:
```
ERROR 23514 (check_violation) no partition of relation "analytics_events" found for row
```

**Solution**: The migration creates partitions for current and next month. Additional partitions are created automatically IF the `ensure_partition_exists` function is called in the code.

**Manual partition creation** (if needed):
```bash
kubectl exec -n rsolv-staging POSTGRES_POD -- psql -U rsolv -d rsolv_staging -c \
  "CREATE TABLE analytics_events_2025_09 PARTITION OF analytics_events 
   FOR VALUES FROM ('2025-09-01') TO ('2025-10-01');"
```

### 3. Asset Compilation and Digests

**Issue**: Production uses digested assets (e.g., `app-8e953c441e7bc0a8f30b3bd585316e47.css`). If assets aren't properly compiled, CSS/JS will 404.

**Requirements**:
- `npm install` must run during build
- `mix assets.deploy` must run to generate digests
- The Dockerfile handles this, but local builds may fail

### 4. Health Check Format

The enhanced health check at `/health` returns:
```json
{
  "status": "ok|warning|unhealthy",
  "timestamp": "2025-08-01 21:00:00.000000Z",
  "clustering": {
    "enabled": true,
    "status": "single_node|healthy|not_configured",
    "current_node": "rsolv@10.42.4.108",
    "connected_nodes": ["rsolv@10.42.5.3"],
    "node_count": 2
  },
  "database": {
    "status": "ok|error",
    "message": "Database connection successful"
  },
  "analytics": {
    "status": "ok|warning|error", 
    "message": "Analytics partition exists for current month"
  }
}
```

Status codes:
- 200: ok or degraded (warning)
- 503: unhealthy (database or critical service down)

## 📋 Complete Deployment Checklist

### Pre-Deployment
- [ ] Ensure secrets exist in target namespace
- [ ] Verify database connection string is correct
- [ ] Check current month analytics partition exists

### Deployment Steps

1. **Build and Push Image**
   ```bash
   docker build -t ghcr.io/rsolv-dev/rsolv-platform:staging .
   docker push ghcr.io/rsolv-dev/rsolv-platform:staging
   ```

2. **Run Migrations** (CRITICAL)
   ```bash
   # Create migration job
   kubectl apply -f k8s/migration-job.yaml
   
   # Or use deployment script
   ./scripts/deploy.sh staging
   ```

3. **Update Deployment**
   ```bash
   kubectl rollout restart deployment/staging-rsolv-platform -n rsolv-staging
   kubectl rollout status deployment/staging-rsolv-platform -n rsolv-staging
   ```

4. **Verify Health**
   ```bash
   curl https://rsolv-staging.com/health | jq .
   ```

### Post-Deployment Verification
- [ ] Health check returns 200 with all services "ok"
- [ ] Homepage loads without 500 error
- [ ] CSS/JS assets load correctly
- [ ] Dark mode toggle works
- [ ] Blog posts are visible
- [ ] Analytics events are being recorded

## 🐛 Common Issues and Solutions

### 1. "No partition found for row" Error
**Cause**: Missing partition for current month
**Fix**: 
```bash
# Create partition manually
kubectl exec -n rsolv-staging POSTGRES_POD -- psql -U rsolv -d rsolv_staging -c \
  "SELECT create_analytics_partition_if_not_exists(CURRENT_DATE);"
```

### 2. CSS/JS Returns 404
**Cause**: Asset digest mismatch
**Fix**: Rebuild image with proper asset compilation:
```bash
# Ensure these steps run in Dockerfile:
RUN npm install
RUN MIX_ENV=prod mix assets.deploy
```

### 3. Health Check Shows Old Format
**Cause**: Old deployment or caching
**Fix**: Force rollout with new image:
```bash
kubectl rollout restart deployment/staging-rsolv-platform -n rsolv-staging
```

### 4. Migrations Fail with "Table already exists"
**Cause**: Partial migration state
**Fix**: Mark existing migrations as complete:
```bash
./scripts/fix_staging_migrations.sh
```

## 🔧 Maintenance Tasks

### Monthly: Create Analytics Partitions
While partitions should auto-create, verify they exist:
```bash
# Check next month's partition exists
kubectl exec -n rsolv-production POSTGRES_POD -- psql -U rsolv -d rsolv_prod -c \
  "SELECT tablename FROM pg_tables WHERE tablename LIKE 'analytics_events_%' ORDER BY tablename;"
```

### Before Major Updates
1. Backup database
2. Test migrations on staging first
3. Verify asset compilation works
4. Check health endpoint changes

## 📝 Blog System Notes

Blog posts are stored as markdown files in `priv/blog/`, NOT in the database. They are:
- Compiled into the release
- Filtered by status (published/draft) and date
- Cached in memory for performance

To add new posts:
1. Add `.md` file to `priv/blog/`
2. Set frontmatter with status and date
3. Rebuild and deploy the application