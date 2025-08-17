# False Positive Cache - Issues Runbook

**Version**: 1.0  
**Date**: 2025-08-17  
**Author**: Platform Team  
**Dashboard**: https://grafana.rsolv.dev/d/fp-cache-production  

## Quick Reference

### Emergency Contacts
- **Platform Team**: On-call rotation
- **Escalation**: CTO/Lead Engineer

### Critical Commands
```bash
# Disable cache immediately
kubectl set env deployment/rsolv-platform FORCE_CACHE_CONTROLLER=false -n rsolv-production

# Clear entire cache
kubectl exec deployment/rsolv-platform -n rsolv-production -- /app/bin/rsolv rpc '
{deleted, _} = Rsolv.Repo.delete_all(Rsolv.ValidationCache.CachedValidation)
IO.puts("Cleared #{deleted} cache entries")
'

# Check cache status
kubectl exec deployment/rsolv-platform -n rsolv-production -- /app/bin/rsolv rpc '
count = Rsolv.Repo.aggregate(Rsolv.ValidationCache.CachedValidation, :count, :id)
IO.puts("Cache entries: #{count}")
'
```

## Issue Categories

### 🔥 **CRITICAL: Cache Corruption**

**Symptoms:**
- Real vulnerabilities marked as false positives
- Customer reports of missed security issues
- Validation accuracy dropping below 95%

**Immediate Response (< 5 minutes):**
```bash
# 1. DISABLE CACHE IMMEDIATELY
kubectl set env deployment/rsolv-platform \
  FORCE_CACHE_CONTROLLER=false \
  -n rsolv-production

# 2. Clear corrupted cache
kubectl exec deployment/rsolv-platform -n rsolv-production -- \
  /app/bin/rsolv rpc '
alias Rsolv.Repo
alias Rsolv.ValidationCache.CachedValidation

{deleted, _} = Repo.delete_all(CachedValidation)
IO.puts("Emergency cache clear: #{deleted} entries deleted")
'

# 3. Verify cache is empty
kubectl exec deployment/rsolv-platform -n rsolv-production -- \
  /app/bin/rsolv rpc '
count = Rsolv.Repo.aggregate(Rsolv.ValidationCache.CachedValidation, :count, :id)
IO.puts("Remaining entries: #{count}")  # Should be 0
'

# 4. Monitor for recovery
kubectl logs -f deployment/rsolv-platform -n rsolv-production | grep -E "(validation|cache)"
```

**Investigation:**
1. Check recent deployments: `kubectl rollout history deployment/rsolv-platform -n rsolv-production`
2. Review SafePatternDetector changes in recent commits
3. Analyze failed validation patterns in logs
4. Run test suite: `cd scripts/cache-testing && ./false-positive-load-test.sh`

**Recovery:**
- Keep cache disabled until root cause identified
- Deploy fix to staging first
- Validate with comprehensive test suite
- Re-enable cache with monitoring

---

### ⚡ **HIGH: Performance Degradation**

**Symptoms:**
- Cache hit rate <50%
- Response time p95 >200ms
- Database connection pool exhaustion
- Customer complaints about slow scans

**Diagnosis Commands:**
```bash
# Check cache hit rate
kubectl exec deployment/rsolv-platform -n rsolv-production -- \
  /app/bin/rsolv rpc '
# Get cache stats from recent validation
# This requires adding cache stats to the response
IO.puts("Check Grafana dashboard for detailed metrics")
'

# Check database connections
kubectl exec deployment/rsolv-platform -n rsolv-production -- \
  /app/bin/rsolv rpc '
status = Rsolv.Repo.query("SELECT * FROM pg_stat_activity WHERE application_name LIKE \"%rsolv%\"")
IO.inspect(status)
'

# Check memory usage
kubectl top pods -n rsolv-production | grep rsolv-platform
```

**Response Actions:**
```bash
# Option 1: Scale up resources
kubectl scale deployment/rsolv-platform --replicas=4 -n rsolv-production

# Option 2: Tune database connections (if needed)
kubectl set env deployment/rsolv-platform \
  DATABASE_POOL_SIZE=20 \
  -n rsolv-production

# Option 3: Temporary cache disable if severe
kubectl set env deployment/rsolv-platform \
  FORCE_CACHE_CONTROLLER=false \
  -n rsolv-production
```

**Investigation:**
1. Review Grafana dashboard for patterns
2. Check for resource constraints
3. Analyze database query performance
4. Review cache key distribution

---

### ⚠️ **MEDIUM: High Cache Miss Rate**

**Symptoms:**
- Cache hit rate 50-70% (expected >70%)
- Increased AST validation API calls
- Higher response times but not critical

**Diagnosis:**
```bash
# Check cache entry count and patterns
kubectl exec deployment/rsolv-platform -n rsolv-production -- \
  /app/bin/rsolv rpc '
alias Rsolv.Repo
alias Rsolv.ValidationCache.CachedValidation

# Count by vulnerability type
results = Repo.all(
  from c in CachedValidation,
  group_by: fragment("validation_result->>\"vulnerability_type\""),
  select: {fragment("validation_result->>\"vulnerability_type\""), count()}
)

IO.puts("Cache distribution by type:")
Enum.each(results, fn {type, count} -> 
  IO.puts("  #{type}: #{count}")
end)
'

# Check for recent cache invalidations
kubectl logs deployment/rsolv-platform -n rsolv-production --since=1h | \
  grep -E "(cache.*invalid|file.*changed)" | tail -20
```

**Common Causes & Solutions:**

**1. File Changes Invalidating Cache**
- **Normal behavior** - files changing frequently
- **Action**: Monitor patterns, no intervention needed
- **Prevention**: Consider longer TTL for stable repositories

**2. Cache Key Collisions**
- **Symptom**: Same file/line showing different results
- **Action**: Review cache key generation logic
- **Fix**: Improve key uniqueness (add file hash)

**3. New Repositories/Patterns**
- **Normal behavior** - new codebases not yet cached
- **Action**: Monitor for stabilization over 24-48 hours
- **Prevention**: Pre-warm cache for major customers

---

### 🔧 **LOW: FunWithFlags Issues**

**Symptoms:**
- Cache controller not starting despite environment variable
- Feature flag showing as disabled in logs
- Cache functionality intermittent

**Diagnosis:**
```bash
# Check environment variable
kubectl get pods -n rsolv-production -l app=rsolv-platform -o yaml | \
  grep -A 5 -B 5 FORCE_CACHE_CONTROLLER

# Check FunWithFlags status
kubectl exec deployment/rsolv-platform -n rsolv-production -- \
  /app/bin/rsolv rpc '
alias FunWithFlags

# Check cache controller flag
cache_enabled = FunWithFlags.enabled?(:cache_controller)
IO.puts("Cache controller flag: #{cache_enabled}")

# Check environment override
env_override = System.get_env("FORCE_CACHE_CONTROLLER") == "true"
IO.puts("Environment override: #{env_override}")
'
```

**Resolution:**
```bash
# Verify environment variable is set correctly
kubectl set env deployment/rsolv-platform \
  FORCE_CACHE_CONTROLLER=true \
  -n rsolv-production

# Restart pods to pick up environment changes
kubectl rollout restart deployment/rsolv-platform -n rsolv-production

# Verify after restart
kubectl rollout status deployment/rsolv-platform -n rsolv-production
```

**Permanent Fix Options** (future consideration):
1. **Cache warming at startup** - Preload FunWithFlags from database
2. **TTL configuration** - Shorter cache TTL for flags
3. **UI toggle** - Manual flag management through admin interface

---

## Monitoring & Alerting

### Key Metrics to Watch

**Cache Performance:**
- Hit rate: >70% (alert if <50%)
- Response time p95: <100ms (alert if >200ms)
- Memory usage: <1GB (alert if >2GB)

**System Health:**
- Error rate: <1% (alert if >5%)
- Database connections: <80% pool (alert if >90%)
- Pod CPU/Memory: <80% (alert if >90%)

**Business Impact:**
- False positive rate: <20% (alert if >30%)
- Customer complaints: Monitor support tickets
- API call volume: Track AST validation reduction

### Grafana Alerts
Dashboard: https://grafana.rsolv.dev/d/fp-cache-production

**Critical Alerts:**
- Cache hit rate <50% for >5 minutes
- Response time p95 >200ms for >10 minutes
- Error rate >5% for >2 minutes

**Warning Alerts:**
- Cache hit rate <70% for >15 minutes
- Memory usage >1GB for >30 minutes
- Database connections >80% for >10 minutes

---

## Debugging Tools

### Cache Analysis Scripts
```bash
# Location: /home/dylan/dev/rsolv/RSOLV-platform/scripts/cache-testing/

# Test cache performance
./false-positive-load-test.sh

# Check specific patterns
./simple-load-test.sh

# Clear cache for testing
./clear-staging-cache.sh  # Update for production
```

### Database Queries
```sql
-- Cache entry distribution
SELECT 
  validation_result->>'vulnerability_type' as vuln_type,
  COUNT(*) as count,
  AVG(EXTRACT(epoch FROM (expires_at - created_at))) as avg_ttl_seconds
FROM cached_validations 
GROUP BY validation_result->>'vulnerability_type';

-- Recent cache hits by repository
SELECT 
  repository,
  COUNT(*) as entries,
  MAX(updated_at) as last_accessed
FROM cached_validations 
WHERE updated_at > NOW() - INTERVAL '24 hours'
GROUP BY repository 
ORDER BY entries DESC 
LIMIT 10;

-- Cache size analysis
SELECT 
  COUNT(*) as total_entries,
  pg_size_pretty(pg_total_relation_size('cached_validations')) as table_size,
  AVG(LENGTH(validation_result::text)) as avg_entry_size_bytes
FROM cached_validations;
```

### Log Analysis
```bash
# Cache-related errors
kubectl logs deployment/rsolv-platform -n rsolv-production --since=1h | \
  grep -E "(cache.*error|validation.*failed)" | tail -50

# Performance issues  
kubectl logs deployment/rsolv-platform -n rsolv-production --since=1h | \
  grep -E "(timeout|slow|performance)" | tail -50

# Database issues
kubectl logs deployment/rsolv-platform -n rsolv-production --since=1h | \
  grep -E "(database|postgres|connection)" | tail -50
```

---

## Prevention & Best Practices

### Regular Maintenance
- **Weekly**: Review cache hit rates and performance trends
- **Monthly**: Analyze cache size growth and cleanup old entries
- **Quarterly**: Review and update cache TTL settings

### Testing Before Changes
1. **Always test in staging first**
2. **Run comprehensive test suite**
3. **Monitor staging for 24 hours before production**
4. **Have rollback plan ready**

### Capacity Planning
- **Monitor cache growth**: Target <10GB total cache size
- **Database connections**: Reserve 20% headroom
- **Memory usage**: Cache should use <25% of pod memory

---

## Escalation Path

### Level 1: Platform Engineer
- Cache performance issues
- Configuration problems
- Routine troubleshooting

### Level 2: Senior Platform Engineer
- Cache corruption investigation
- Database performance issues
- Complex debugging scenarios

### Level 3: CTO/Architecture Team
- System design changes
- Major performance overhauls
- Customer-impacting incidents

**Always escalate if:**
- Customer security is at risk
- System is completely down
- Data integrity is questioned
- Issue exceeds individual expertise

---

**Remember**: When in doubt, disable cache first and investigate safely.  
**The system works without cache - it just performs slower.**