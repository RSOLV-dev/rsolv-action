# False Positive Cache - Production Rollout Plan

**Date**: 2025-08-17  
**Author**: Platform Team  
**Status**: Ready for Execution  
**Staging Image**: `staging-detector-fix-20250816-212842`  
**Target**: Production deployment with zero downtime  

## Pre-Deployment Checklist

### ✅ **Staging Validation Complete**
- [x] 100% cache hit rate for false positives
- [x] 0% false negatives (all real vulnerabilities detected)
- [x] <50ms response time for cache hits
- [x] Grafana dashboard deployed and monitoring
- [x] Load testing passed (100 requests, 100% hit rate)
- [x] FunWithFlags workaround validated (`FORCE_CACHE_CONTROLLER=true`)

### ✅ **Infrastructure Ready**
- [x] PostgreSQL schema deployed (CachedValidation table)
- [x] SafePatternDetector logic fixed and tested
- [x] Monitoring dashboard configured
- [x] Test scripts organized and documented

## Deployment Strategy

### Phase 1: Pre-Production Setup (30 minutes)

#### 1.1 Build Production Image
```bash
cd /home/dylan/dev/rsolv/RSOLV-platform

# Tag current staging image for production
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
PROD_TAG="prod-cache-${TIMESTAMP}"

# Option A: Promote staging image
docker tag ghcr.io/rsolv-dev/rsolv-platform:staging-detector-fix-20250816-212842 \
  ghcr.io/rsolv-dev/rsolv-platform:${PROD_TAG}

docker push ghcr.io/rsolv-dev/rsolv-platform:${PROD_TAG}

# Option B: Fresh build (if needed)
# docker build -t ghcr.io/rsolv-dev/rsolv-platform:${PROD_TAG} .
# docker push ghcr.io/rsolv-dev/rsolv-platform:${PROD_TAG}
```

#### 1.2 Deploy Production Grafana Dashboard
```bash
# Create production dashboard from staging
cd monitoring/grafana-dashboards
sed 's/staging/production/g; s/rsolv-staging/rsolv-production/g' \
  false-positive-cache-staging.json > false-positive-cache-production.json

# Deploy to production
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: false-positive-cache-dashboard-prod
  namespace: monitoring
  labels:
    grafana_dashboard: "1"
data:
  false-positive-cache-prod.json: |
$(cat false-positive-cache-production.json | sed 's/^/    /')
EOF

kubectl rollout restart deployment/grafana -n monitoring
```

#### 1.3 Verify Database Migration
```bash
# Check CachedValidation table exists in production
kubectl exec deployment/rsolv-platform -n rsolv-production -- \
  /app/bin/rsolv rpc '
alias Rsolv.Repo
alias Rsolv.ValidationCache.CachedValidation

# Verify table exists and is empty
count = Repo.aggregate(CachedValidation, :count, :id)
IO.puts("Production cache entries: #{count}")
'
```

### Phase 2: Blue-Green Deployment (15 minutes)

#### 2.1 Update Deployment
```bash
# Set the production image
kubectl set image deployment/rsolv-platform \
  rsolv-platform=ghcr.io/rsolv-dev/rsolv-platform:${PROD_TAG} \
  -n rsolv-production

# Set cache controller environment variable
kubectl set env deployment/rsolv-platform \
  FORCE_CACHE_CONTROLLER=true \
  -n rsolv-production
```

#### 2.2 Monitor Rollout
```bash
# Watch deployment progress
kubectl rollout status deployment/rsolv-platform -n rsolv-production --timeout=600s

# Verify all pods are running
kubectl get pods -n rsolv-production -l app=rsolv-platform
```

### Phase 3: Production Validation (20 minutes)

#### 3.1 Health Check
```bash
# Check API health
curl -f https://api.rsolv.dev/health || echo "Health check failed"

# Verify cache endpoint responds
curl -X POST "https://api.rsolv.dev/api/v1/vulnerabilities/validate" \
  -H "X-API-Key: $PROD_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerabilities": [{
      "type": "sql-injection",
      "locations": [{"file_path": "test.js", "line": 1, "is_primary": true}],
      "code": "db.query(\"SELECT * FROM users WHERE id = $1\", [userId])"
    }],
    "files": {"test.js": {"content": "// test", "hash": "sha256:test"}},
    "repository": "health-check/cache-test"
  }' | jq '.validated[0].isValid'
```

#### 3.2 Cache Performance Test
```bash
# Run production cache test
cd scripts/cache-testing

# Update test script for production
sed 's/staging_test_F344F8491174D8F27943D0DB12A4A13D/$PROD_API_KEY/g; 
     s/api.rsolv-staging.com/api.rsolv.dev/g' \
  false-positive-load-test.sh > prod-cache-test.sh

chmod +x prod-cache-test.sh
./prod-cache-test.sh
```

#### 3.3 Monitor Dashboard
- Access: https://grafana.rsolv.dev/d/fp-cache-production
- Verify metrics are flowing
- Check for any error spikes

### Phase 4: Traffic Validation (30 minutes)

#### 4.1 Monitor Production Traffic
```bash
# Watch cache metrics
kubectl logs -f deployment/rsolv-platform -n rsolv-production | grep "cache"

# Monitor for errors
kubectl logs deployment/rsolv-platform -n rsolv-production --since=10m | grep -E "(ERROR|WARN)"
```

#### 4.2 Performance Verification
- Cache hit rate: Target >70%
- Response time p95: Target <100ms
- Error rate: Target <1%

## Rollback Plan

### Immediate Rollback (< 5 minutes)
```bash
# Option 1: Revert image
kubectl rollout undo deployment/rsolv-platform -n rsolv-production

# Option 2: Disable cache
kubectl set env deployment/rsolv-platform \
  FORCE_CACHE_CONTROLLER=false \
  -n rsolv-production

# Option 3: Remove environment variable entirely
kubectl set env deployment/rsolv-platform \
  FORCE_CACHE_CONTROLLER- \
  -n rsolv-production
```

### Emergency Response
If cache causes issues:
1. **Immediate**: Disable cache controller via env var
2. **Clear cache**: Run cache clear script if corruption suspected
3. **Monitor**: Watch error rates drop
4. **Investigate**: Use runbook for troubleshooting

## Success Criteria

### Deployment Success
- [x] All pods running healthy
- [x] API responds to health checks
- [x] Cache endpoint returns valid responses
- [x] No error spikes in logs

### Performance Success (1 hour post-deployment)
- [ ] Cache hit rate >70%
- [ ] Response time p95 <100ms
- [ ] Error rate <1%
- [ ] No customer complaints

### 24-Hour Success
- [ ] Cache hit rate >80%
- [ ] Average response time <50ms
- [ ] Zero cache-related incidents
- [ ] Customer feedback positive

## Risk Mitigation

### High Risk - Cache Corruption
- **Detection**: Monitoring alerts, customer reports
- **Response**: Clear cache, investigate pattern
- **Prevention**: Input validation, comprehensive testing

### Medium Risk - Performance Degradation
- **Detection**: Dashboard alerts, response time monitoring
- **Response**: Tune cache parameters, scale resources
- **Prevention**: Load testing, gradual rollout

### Low Risk - FunWithFlags Issues
- **Detection**: Feature flag logs, cache miss spikes
- **Response**: Verify env var setting, restart pods
- **Prevention**: Document workaround, monitor startup

## Communication Plan

### Internal
- **Pre-deployment**: Document plan completion
- **During deployment**: Monitor dashboards
- **Post-deployment**: Validate success criteria
- **24-hour review**: Performance assessment

### Customer Impact
- **Expected**: Faster response times, fewer false positives
- **Monitoring**: Customer feedback, support tickets
- **Communication**: No downtime expected, improved experience

## Contact Information

**Deployment Lead**: Platform Team  
**Emergency Contact**: On-call rotation  
**Grafana Dashboard**: https://grafana.rsolv.dev/d/fp-cache-production  
**Runbook**: CACHE-ISSUES-RUNBOOK.md  

---

**This plan assumes production environment mirrors staging configuration.**  
**Validate all kubectl commands in staging before production execution.**