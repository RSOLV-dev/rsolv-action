# False Positive Cache - Staging Validation Plan

**Date**: 2025-08-17  
**Objective**: Thoroughly validate cache behavior before production deployment

## Understanding the FunWithFlags Issue

### Root Cause
FunWithFlags uses an ETS table for caching that:
1. **Is created at startup** by the FunWithFlags.Supervisor
2. **Does NOT automatically populate from database** on startup
3. **Only populates lazily** as flags are requested
4. **Uses cache-bust notifications** to sync between nodes

### Why Our Issue Occurs
1. Migration sets flag to `true` in database
2. Application starts with empty ETS cache
3. First request to `FunWithFlags.enabled?(:false_positive_caching)` returns `{:ok, false}` (default)
4. This `false` value is cached in ETS
5. Subsequent requests use cached `false` value
6. Cache-bust notifications don't help because no flag is being *changed*

### Permanent Solutions

#### Option 1: Warm Cache on Startup
```elixir
# In application.ex after supervisor starts
def start(_type, _args) do
  children = [...]
  
  opts = [strategy: :one_for_one, name: Rsolv.Supervisor]
  result = Supervisor.start_link(children, opts)
  
  # Warm the cache for critical flags
  Task.start(fn ->
    Process.sleep(100) # Let FunWithFlags initialize
    FunWithFlags.enabled?(:false_positive_caching)
  end)
  
  result
end
```

#### Option 2: Configure Cache TTL
```elixir
# In config.exs
config :fun_with_flags, :cache,
  enabled: true,
  ttl: 300 # 5 minutes - forces periodic DB refresh
```

#### Option 3: Use FunWithFlags UI
- Access at `/feature-flags` in staging
- Manually toggle flag to trigger cache-bust notification
- This properly syncs all nodes

## Staging Validation Tests

### 1. Performance Tests

#### A. Load Test with Cache
```bash
# Run 1000 requests to measure cache performance
for i in {1..1000}; do
  curl -X POST https://api.rsolv-staging.com/api/v1/vulnerabilities/validate \
    -H "X-API-Key: staging_test_F344F8491174D8F27943D0DB12A4A13D" \
    -H "Content-Type: application/json" \
    -d "{\"vulnerabilities\":[{\"type\":\"sql-injection\",\"locations\":[{\"file_path\":\"load/test$((i % 10)).js\",\"line\":$i,\"is_primary\":true}],\"code\":\"db.query(input)\"}],\"files\":{\"load/test$((i % 10)).js\":{\"content\":\"test\",\"hash\":\"sha256:load$((i % 10))\"}}},\"repository\":\"staging-test-org/load-test\"}" &
  
  # Rate limit to avoid overwhelming
  if [ $((i % 50)) -eq 0 ]; then
    wait
  fi
done
wait
```

#### B. Measure Response Times
- **Without cache**: Expect 500-1000ms per validation
- **With cache hit**: Expect <50ms per validation
- **Target**: >80% cache hit rate in production scenarios

### 2. Correctness Tests

#### A. False Positive Detection
```bash
# Test known false positives are cached correctly
./test-known-false-positives.sh

# Verify:
# - SQL injection in test fixtures cached as false positive
# - XSS in React's dangerouslySetInnerHTML cached correctly
# - Command injection in build scripts cached appropriately
```

#### B. True Positive Detection
```bash
# Ensure real vulnerabilities are NOT marked as false positives
./test-real-vulnerabilities.sh

# Verify:
# - User input flows are detected
# - Unsafe patterns are flagged
# - Cache doesn't hide real issues
```

### 3. Cache Invalidation Tests

#### A. File Modification
```bash
# Test 1: Minor change (comment added)
# Test 2: Code change (variable renamed)
# Test 3: Line number change (newlines added)
# All should invalidate cache due to hash change
```

#### B. TTL Expiration
```bash
# Can't test 90-day TTL directly, but verify:
kubectl exec -n rsolv-staging deployment/staging-rsolv-platform -- \
  /app/bin/rsolv eval 'Rsolv.Repo.query!("SELECT ttl_expires_at FROM cached_validations ORDER BY cached_at DESC LIMIT 5")'
```

### 4. Multi-Node Tests

#### A. Cache Consistency
```bash
# Get both pod names
PODS=$(kubectl get pods -n rsolv-staging -l app=staging-rsolv-platform -o name)

# Make request to pod 1 (creates cache entry)
# Make request to pod 2 (should also use cache via shared DB)
```

#### B. Rolling Deployment
```bash
# Simulate production deployment
kubectl set image deployment/staging-rsolv-platform \
  rsolv-platform=ghcr.io/rsolv-dev/rsolv-platform:new-version \
  -n rsolv-staging

# Monitor for errors during rollout
kubectl logs -f -n rsolv-staging -l app=staging-rsolv-platform
```

### 5. Edge Cases

#### A. Large Files
```bash
# Test with 10MB source file
# Verify cache handles large content appropriately
```

#### B. High Concurrency
```bash
# 100 simultaneous requests for same vulnerability
# Verify no race conditions in cache writes
```

#### C. Repository Isolation
```bash
# Test same file/line in different repos
# Verify cache keys properly scoped
```

## Production Deployment Checklist

### Pre-Deployment
- [ ] Cache hit rate >70% in staging for 24 hours
- [ ] No cache-related errors in logs for 48 hours
- [ ] Performance metrics meet targets (<50ms for cache hits)
- [ ] Cache invalidation verified working
- [ ] Database load reduced by >50% with cache enabled

### Deployment Steps
1. **Set environment variable** in production
   ```bash
   kubectl set env deployment/production-rsolv-platform \
     FORCE_CACHE_CONTROLLER=true -n rsolv-production
   ```

2. **Deploy with rolling update**
   ```bash
   kubectl set image deployment/production-rsolv-platform \
     rsolv-platform=ghcr.io/rsolv-dev/rsolv-platform:production-cache \
     -n rsolv-production
   ```

3. **Monitor closely**
   ```bash
   # Watch logs
   kubectl logs -f -n rsolv-production -l app=production-rsolv-platform
   
   # Check metrics
   curl https://api.rsolv.dev/metrics | grep cache
   ```

### Rollback Plan
```bash
# If issues occur, immediately:
kubectl set env deployment/production-rsolv-platform \
  FORCE_CACHE_CONTROLLER=false -n rsolv-production

# This disables cache without redeployment
```

## Monitoring Queries

### Cache Performance
```sql
-- Cache hit rate by hour
SELECT 
  date_trunc('hour', cached_at) as hour,
  COUNT(*) as total_cached,
  AVG(EXTRACT(EPOCH FROM (ttl_expires_at - cached_at))) / 86400 as avg_ttl_days
FROM cached_validations
WHERE cached_at > NOW() - INTERVAL '24 hours'
GROUP BY hour
ORDER BY hour DESC;
```

### Cache Size
```sql
-- Total cache entries and size
SELECT 
  COUNT(*) as total_entries,
  pg_size_pretty(SUM(pg_column_size(full_result))) as cache_size,
  COUNT(DISTINCT forge_account_id) as unique_accounts,
  COUNT(DISTINCT repository) as unique_repos
FROM cached_validations
WHERE invalidated_at IS NULL;
```

## Success Criteria

1. **Performance**
   - Cache hit rate >70% in typical usage
   - Response time <50ms for cache hits
   - Database load reduced by >50%

2. **Correctness**
   - Zero false negatives (real vulnerabilities missed)
   - False positive detection accuracy maintained
   - Cache invalidation working reliably

3. **Stability**
   - No cache-related errors in 48 hours
   - Successful rolling deployments
   - Multi-node consistency verified

## Next Steps After Validation

1. **Remove environment variable override**
   - Implement cache warming on startup
   - Or configure appropriate cache TTL
   - Or fix FunWithFlags initialization

2. **Add production monitoring**
   - Grafana dashboard for cache metrics
   - Alerts for low hit rates
   - Database load comparison graphs

3. **Document learnings**
   - Update RFC-045 with production metrics
   - Create runbook for cache issues
   - Share performance improvements with team