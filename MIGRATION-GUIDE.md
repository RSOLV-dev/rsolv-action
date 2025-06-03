# Database Migration Guide

## The Idiomatic Elixir/Phoenix Approach

In production Elixir/Phoenix applications, there are three main approaches to running migrations:

### 1. Init Container (Recommended for Kubernetes)
Migrations run automatically before each deployment using an init container. This ensures migrations are always run before the new code starts.

```bash
# Deploy with automatic migrations
kubectl apply -f k8s/deployment-with-migrations.yaml
```

**Pros:**
- Automatic - migrations run with every deployment
- Safe - new code won't start until migrations succeed
- Idempotent - Ecto tracks which migrations have run

**Cons:**
- Slower deployments
- All pods wait for migrations to complete

### 2. One-off Command (Recommended for manual migrations)
Run migrations on demand using an existing pod:

```bash
# Run migrations manually
./scripts/run-migrations-prod.sh

# Or directly:
kubectl exec deployment/rsolv-api -- bin/rsolv_api eval "RsolvApi.Release.migrate()"
```

**Pros:**
- Fast and simple
- Can be run anytime
- Good for debugging

**Cons:**
- Manual process
- Must remember to run before deploying breaking changes

### 3. Separate Migration Job (For complex scenarios)
Run migrations as a Kubernetes Job:

```bash
kubectl apply -f k8s/migration-job.yaml
kubectl wait --for=condition=complete job/rsolv-api-migrate
```

**Pros:**
- Clean separation of concerns
- Can add pre/post migration hooks
- Good for long-running migrations

**Cons:**
- More complex setup
- Requires cleanup after completion

## Best Practices

1. **Always test migrations locally first:**
   ```bash
   make migrate-dev
   ```

2. **For breaking changes:**
   - Deploy migrations first
   - Then deploy code changes
   - Use feature flags if needed

3. **For rollbacks:**
   ```bash
   kubectl exec deployment/rsolv-api -- bin/rsolv_api eval "RsolvApi.Release.rollback(RsolvApi.Repo, version)"
   ```

4. **Check migration status:**
   ```bash
   kubectl exec deployment/rsolv-api -- bin/rsolv_api eval "Ecto.Migrator.migrations(RsolvApi.Repo)"
   ```

## Phoenix-Specific Notes

Phoenix releases use Elixir's built-in release functionality. The `RsolvApi.Release` module is the standard pattern for production tasks. This approach:

- Loads the application configuration
- Ensures database connections work
- Handles multiple repos if needed
- Provides consistent error handling

This is more idiomatic than external scripts or complex orchestration.