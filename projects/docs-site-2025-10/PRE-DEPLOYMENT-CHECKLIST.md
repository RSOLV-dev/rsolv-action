# Pre-Deployment Checklist

**Date**: 2025-08-17
**Deployment**: False Positive Cache to Production

## ✅ **CRITICAL - Must Complete Before Deployment**

### 1. Database Schema Issue Identified ⚠️
- [x] **Found**: Production lacks CachedValidation table
- [x] **Current Production Image**: `prod-fix-20250816-093716` (outdated)
- [x] **Staging Image**: `staging-detector-fix-20250816-212842` (has migration)
- [x] **Solution**: Deploy staging image which includes migration `20250817000713_create_cached_validations.exs`

### 2. Configuration Backup ✅
- [x] **Backup Created**: `backup-prod-deployment-20250816-225116.yaml`
- [x] **Location**: `/home/dylan/dev/rsolv/RSOLV-platform/`
- [x] **Content**: Current production deployment configuration

### 3. Update Rollout Plan ⚠️
The rollout plan needs minor adjustment:
- **Issue**: Assumes table exists, but we need to deploy image + run migration first
- **Solution**: Deploy staging image which contains the migration

## 🔧 **Recommended Additional Prep**

### 4. Test Rollback Procedure
```bash
# Test in staging first
kubectl set env deployment/staging-rsolv-platform \
  FORCE_CACHE_CONTROLLER=false \
  -n rsolv-staging

# Verify cache disabled
curl -X POST "https://api.rsolv-staging.com/api/v1/vulnerabilities/validate" \
  -H "X-API-Key: staging_test_F344F8491174D8F27943D0DB12A4A13D" \
  -H "Content-Type: application/json" \
  -d '{"vulnerabilities": [{"type": "sql-injection", "locations": [{"file_path": "test.js", "line": 1, "is_primary": true}], "code": "test"}], "files": {"test.js": {"content": "test", "hash": "test"}}, "repository": "test/test"}' | jq '.validated[0].fromCache'

# Should return null (not from cache)
```

### 5. Production API Key Setup
```bash
# Need to set up production API key for testing
# This should be done through the admin interface or database
export PROD_API_KEY="your-production-api-key"
```

### 6. Monitoring Alerts (Can be done post-deployment)
- Cache hit rate <50% for >5 minutes
- Response time p95 >200ms for >10 minutes
- Error rate >5% for >2 minutes

## 📋 **Updated Deployment Strategy**

Given the database schema issue, here's the adjusted approach:

### Phase 1: Deploy Image with Migration (45 minutes)
```bash
# 1. Deploy staging image to production (includes migration)
kubectl set image deployment/rsolv-platform \
  rsolv-platform=ghcr.io/rsolv-dev/rsolv-platform:staging-detector-fix-20250816-212842 \
  -n rsolv-production

# 2. Wait for rollout
kubectl rollout status deployment/rsolv-platform -n rsolv-production

# 3. Run migration to create CachedValidation table
kubectl exec deployment/rsolv-platform -n rsolv-production -- \
  /app/bin/rsolv eval "Rsolv.Release.migrate"

# 4. Verify table exists
kubectl exec deployment/rsolv-platform -n rsolv-production -- \
  /app/bin/rsolv rpc 'IO.puts("Table count: #{Rsolv.Repo.aggregate(Rsolv.ValidationCache.CachedValidation, :count, :id)}")'
```

### Phase 2: Enable Cache (15 minutes)
```bash
# 5. Enable cache controller
kubectl set env deployment/rsolv-platform \
  FORCE_CACHE_CONTROLLER=true \
  -n rsolv-production

# 6. Monitor for startup
kubectl logs -f deployment/rsolv-platform -n rsolv-production | grep -E "(cache|startup)"
```

### Phase 3: Validation & Monitoring (30 minutes)
- Follow original rollout plan validation steps
- Test cache functionality
- Monitor dashboard

## 🚨 **Emergency Rollback**

If anything goes wrong:

```bash
# Option 1: Disable cache (fastest)
kubectl set env deployment/rsolv-platform \
  FORCE_CACHE_CONTROLLER=false \
  -n rsolv-production

# Option 2: Revert to backup deployment
kubectl apply -f backup-prod-deployment-20250816-225116.yaml

# Option 3: Manual rollback
kubectl rollout undo deployment/rsolv-platform -n rsolv-production
```

## ✅ **Ready to Proceed?**

**Prerequisites Met:**
- [x] Database migration identified and planned
- [x] Backup configuration saved
- [x] Deployment strategy updated
- [x] Emergency rollback procedures ready

**Optional (Recommended):**
- [ ] Test rollback procedure in staging
- [ ] Set up production API key
- [ ] Configure monitoring alerts

**Decision:** The system is ready for deployment with the updated strategy that addresses the database schema requirement.

---

**Note**: The original rollout plan assumed the table existed. This checklist updates the approach to deploy the image with migration first, then enable cache functionality.