# RFC-060 Phase 5.4: Production Deployment - Checklist

**Date**: 2025-10-12
**Phase**: 5.4 - Production Deployment
**Target**: rsolv.dev (production environment)
**Status**: 🔄 PRE-DEPLOYMENT VALIDATION

## Pre-Deployment Risk Assessment

### High-Confidence Items ✅
- [x] PromEx metrics collection infrastructure deployed and tested
- [x] Telemetry instrumentation code complete
- [x] /metrics endpoint functional and returning data
- [x] Grafana dashboard imported and configured
- [x] Prometheus alert rules loaded
- [x] End-to-end pipeline validated with synthetic data

### Medium-Confidence Items ⚠️
- [ ] Real RSOLV-action workflow tested on staging (not just synthetic API calls)
- [ ] Full three-phase flow validated (SCAN → VALIDATE → MITIGATE)
- [ ] Metrics from actual Claude Code SDK test generation
- [ ] Dashboard panels verified with real data
- [ ] Alert thresholds validated with realistic values

### Recommendation

**RECOMMENDED**: Execute staging validation workflow before production deployment

**Why?**
1. We've only tested with synthetic API POST requests
2. Haven't validated metrics from actual RSOLV-action + Claude Code SDK execution
3. Dashboard panels may need query adjustments based on real data
4. Alert thresholds should be validated before production alerting

**If we skip staging validation:**
- Risk: Dashboard panels may show "No data" due to query mismatches
- Risk: Alert thresholds may be incorrectly tuned
- Risk: Unexpected metric label combinations
- Mitigation: Can fix issues in production quickly via ConfigMap updates

## Pre-Deployment Validation (Recommended)

### Staging Workflow Test

**Objective**: Run real RSOLV-action workflow against staging API with executable tests enabled

**Steps**:

#### 1. Prepare Test Repository
```bash
cd /tmp/local-nodegoat-test
git checkout main
git pull origin main
```

#### 2. Create Test Workflow File
```yaml
# .github/workflows/rsolv-staging-test.yml
name: RSOLV Staging Test
on:
  workflow_dispatch:

jobs:
  test-rsolv:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - uses: RSOLV-dev/rsolv-action@v3.7.x
        with:
          rsolvApiKey: ${{ secrets.STAGING_API_KEY }}
          api_url: 'https://rsolv-staging.com'
          mode: 'full'
          executable_tests: 'true'
          claude_max_turns: '5'
          max_issues: '1'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

#### 3. Execute Workflow
```bash
# Set up secrets
gh secret set STAGING_API_KEY --body "rsolv_9nk_8xwsWn9wykMTRaIr9PUra_jBK3we6GbFKDZ4" --repo RSOLV-dev/nodegoat-vulnerability-demo

# Trigger workflow
gh workflow run rsolv-staging-test.yml --repo RSOLV-dev/nodegoat-vulnerability-demo

# Monitor execution
gh run list --workflow=rsolv-staging-test.yml --repo RSOLV-dev/nodegoat-vulnerability-demo
gh run watch --repo RSOLV-dev/nodegoat-vulnerability-demo
```

#### 4. Verify Metrics Collection

**Check Prometheus**:
```bash
# Port-forward Prometheus
kubectl port-forward -n monitoring service/prometheus-service 9090:9090 &

# Query validation metrics
curl -s 'http://localhost:9090/api/v1/query?query=rsolv_validation_executions_total{environment="staging"}' | jq '.data.result'

# Query mitigation metrics
curl -s 'http://localhost:9090/api/v1/query?query=rsolv_mitigation_executions_total{environment="staging"}' | jq '.data.result'

# Check trust scores
curl -s 'http://localhost:9090/api/v1/query?query=rsolv_mitigation_trust_score_value_sum{environment="staging"}' | jq '.data.result'
```

**Check Grafana Dashboard**:
```bash
# Port-forward Grafana
kubectl port-forward -n monitoring service/grafana-service 3000:3000 &

# Open dashboard in browser
open "http://localhost:3000/d/rfc-060-validation?orgId=1&var-environment=staging"

# Or query via API
curl -s --user admin:RSolvMonitor123! 'http://localhost:3000/api/datasources/proxy/1/api/v1/query?query=rsolv_validation_executions_total{environment="staging"}' | jq '.'
```

**Expected Results**:
- ✅ Validation execution counter incremented
- ✅ Test generation events captured
- ✅ Validation duration histogram populated
- ✅ Mitigation execution counter incremented (if mitigation ran)
- ✅ Trust score recorded (if PR created)
- ✅ Dashboard panels display data
- ✅ No errors in Prometheus/Grafana logs

#### 5. Validation Checklist

- [ ] SCAN phase completed successfully
- [ ] VALIDATE phase created validation branch
- [ ] Tests generated via Claude Code SDK
- [ ] Tests executed (pass/fail doesn't matter, just that they ran)
- [ ] Validation metrics appeared in /metrics endpoint
- [ ] Prometheus scraped validation metrics
- [ ] Grafana dashboard panels populated with data
- [ ] No query errors in dashboard panels
- [ ] MITIGATE phase ran (if validation succeeded)
- [ ] Trust score calculated and recorded
- [ ] PR created (if trust score above threshold)
- [ ] All three phases have metrics in Prometheus

### Skip Validation Decision Point

**Option A: Proceed After Validation** ✅ RECOMMENDED
- All tests pass → High confidence deployment
- Dashboard verified → No surprises in production
- Alert thresholds validated → Accurate alerting

**Option B: Deploy Without Validation** ⚠️ ACCEPTABLE
- Infrastructure proven → Core pipeline works
- Can fix issues quickly → ConfigMap updates don't require deployment
- Lower risk → Metrics are observability, not critical path

**Decision**: [ ] Option A (validate) / [ ] Option B (deploy now)

---

## Production Deployment Checklist

### Pre-Deployment Verification

#### Environment Check
- [ ] Production cluster accessible: `kubectl cluster-info`
- [ ] Correct namespace targeted: `rsolv-production`
- [ ] Docker registry accessible: `docker login ghcr.io`
- [ ] Build environment ready: `DOCKER_HOST=10.5.0.5`

#### Code Review
- [ ] All Phase 5.2 code merged to main branch
- [ ] Git status clean: `git status` (no uncommitted changes)
- [ ] Latest code pulled: `git pull origin main`
- [ ] Version tagged: `git tag v0.1.0-rfc060-phase5` (optional)

#### Configuration Review
- [ ] `config/runtime.exs` monitoring config present (lines 172-175)
- [ ] `lib/rsolv/application.ex` includes `Rsolv.PromEx` in supervision tree
- [ ] `lib/rsolv/prom_ex/validation_plugin.ex` complete
- [ ] `lib/rsolv_web/router.ex` /metrics endpoint public
- [ ] No staging-specific configuration in production code

#### Secrets Verification
- [ ] Production secrets exist: `kubectl get secrets -n rsolv-production`
- [ ] All secrets have values (not empty):
  - [ ] `DATABASE_URL` (postgres:// connection string)
  - [ ] `SECRET_KEY_BASE` (64 hex chars)
  - [ ] `ANTHROPIC_API_KEY` (for validation tests)
  - [ ] `OPENAI_API_KEY` (backup)
  - [ ] `POSTMARK_API_KEY` (email notifications)

### Build Phase

#### Docker Image Build
```bash
# Set build context
cd ~/dev/rsolv
export DOCKER_HOST=10.5.0.5

# Build image with production tag
docker build \
  -t ghcr.io/rsolv-dev/rsolv-platform:production-$(date +%Y%m%d-%H%M%S) \
  -t ghcr.io/rsolv-dev/rsolv-platform:production-rfc060-phase5 \
  -t ghcr.io/rsolv-dev/rsolv-platform:production-latest \
  -f Dockerfile \
  .

# Verify build succeeded
docker images | grep rsolv-platform | grep production
```

**Build Checklist**:
- [ ] Build completed without errors
- [ ] Image tagged with timestamp
- [ ] Image tagged with phase identifier
- [ ] Image tagged with 'latest'
- [ ] Image size reasonable (<1GB)

#### Push to Registry
```bash
# Push all tags
docker push ghcr.io/rsolv-dev/rsolv-platform:production-$(date +%Y%m%d-%H%M%S)
docker push ghcr.io/rsolv-dev/rsolv-platform:production-rfc060-phase5
docker push ghcr.io/rsolv-dev/rsolv-platform:production-latest

# Verify push succeeded
gh api /user/packages/container/rsolv-platform/versions | jq '.[0:3] | .[] | {name: .name, created_at: .created_at}'
```

**Push Checklist**:
- [ ] All tags pushed successfully
- [ ] Images visible in GitHub Container Registry
- [ ] Image manifest correct (multi-arch if applicable)

### Deployment Phase

#### Backup Current State
```bash
# Backup current deployment
kubectl get deployment rsolv-platform -n rsolv-production -o yaml > /tmp/production-deployment-backup-$(date +%Y%m%d).yaml

# Backup current configmaps
kubectl get configmap -n rsolv-production -o yaml > /tmp/production-configmaps-backup-$(date +%Y%m%d).yaml

# Backup current secrets
kubectl get secrets -n rsolv-production -o yaml > /tmp/production-secrets-backup-$(date +%Y%m%d).yaml

echo "Backups created in /tmp/"
```

**Backup Checklist**:
- [ ] Deployment YAML backed up
- [ ] ConfigMaps backed up
- [ ] Secrets backed up
- [ ] Backups timestamped
- [ ] Backup location documented

#### Update Deployment Image
```bash
# Get the image tag to deploy
IMAGE_TAG="production-$(date +%Y%m%d-%H%M%S)"

# Update deployment with new image
kubectl set image deployment/rsolv-platform \
  rsolv-platform=ghcr.io/rsolv-dev/rsolv-platform:${IMAGE_TAG} \
  -n rsolv-production

# OR use kustomize if you have overlays
cd ~/dev/rsolv-infrastructure/kubernetes/overlays/production
kustomize edit set image ghcr.io/rsolv-dev/rsolv-platform:${IMAGE_TAG}
kubectl apply -k .
```

**Image Update Checklist**:
- [ ] Correct image tag used
- [ ] Deployment updated successfully
- [ ] Old image tag documented for rollback

#### Monitor Deployment
```bash
# Watch rollout status
kubectl rollout status deployment/rsolv-platform -n rsolv-production --timeout=5m

# Check pod status
kubectl get pods -n rsolv-production -l app=rsolv-platform

# Check new pod logs
kubectl logs -n rsolv-production -l app=rsolv-platform --tail=50 --follow
```

**Deployment Monitoring**:
- [ ] Rollout completed successfully
- [ ] New pods in Running state
- [ ] Old pods terminated gracefully
- [ ] No CrashLoopBackOff errors
- [ ] Application logs show healthy startup
- [ ] PromEx started in logs: `grep -i "promex" logs`

#### Health Checks
```bash
# Check /health endpoint
curl -s https://rsolv.dev/health | jq '.'

# Check /metrics endpoint
curl -s https://rsolv.dev/metrics | head -50

# Check for RFC-060 metrics
curl -s https://rsolv.dev/metrics | grep "rsolv_validation\|rsolv_mitigation"

# Verify response time
time curl -s https://rsolv.dev/health
```

**Health Check Results**:
- [ ] /health returns 200 OK
- [ ] /metrics returns Prometheus format
- [ ] RFC-060 metrics defined (may have 0 values initially)
- [ ] Response times < 2 seconds
- [ ] No 5xx errors
- [ ] SSL certificate valid

#### Database Migrations
```bash
# Check if migrations needed
kubectl exec -n rsolv-production deployment/rsolv-platform -- bin/rsolv eval 'Ecto.Migrator.migrations(Rsolv.Repo, "priv/repo/migrations") |> IO.inspect'

# Run migrations if needed
kubectl exec -n rsolv-production deployment/rsolv-platform -- bin/rsolv eval 'Ecto.Migrator.run(Rsolv.Repo, "priv/repo/migrations", :up, all: true)'

# Verify migrations
kubectl exec -n rsolv-production deployment/rsolv-platform -- bin/rsolv eval 'Ecto.Migrator.with_repo(Rsolv.Repo, &Ecto.Migrator.migrated_versions(&1)) |> IO.inspect'
```

**Migration Checklist**:
- [ ] No new migrations required (RFC-060 didn't add schema changes)
- [ ] OR migrations ran successfully
- [ ] No migration errors in logs
- [ ] Database schema matches expectations

### Monitoring Configuration

#### Verify Prometheus Scraping Production
```bash
# Port-forward Prometheus
kubectl port-forward -n monitoring service/prometheus-service 9090:9090 &

# Check if production target is being scraped
curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | select(.labels.job == "rsolv-platform") | {job: .labels.job, health: .health, scrapeUrl: .scrapeUrl, lastScrape: .lastScrape}'

# Verify metrics flowing
sleep 20  # Wait for first scrape
curl -s 'http://localhost:9090/api/v1/query?query=rsolv_validation_executions_total{environment="production"}' | jq '.'
```

**Prometheus Checklist**:
- [ ] Production target status: "up"
- [ ] Last scrape within last 15 seconds
- [ ] No scrape errors
- [ ] RFC-060 metrics present (may be 0 initially)
- [ ] Environment label: `environment="production"`

#### Verify Grafana Dashboard Shows Production
```bash
# Port-forward Grafana
kubectl port-forward -n monitoring service/grafana-service 3000:3000 &

# Check dashboard panels for production data
open "http://localhost:3000/d/rfc-060-validation?orgId=1&var-environment=production"

# Or query via API
curl -s --user admin:RSolvMonitor123! 'http://localhost:3000/api/datasources/proxy/1/api/v1/query?query=rsolv_validation_executions_total{environment="production"}' | jq '.'
```

**Grafana Checklist**:
- [ ] Dashboard accessible
- [ ] Environment variable filter shows "production"
- [ ] Panels configured to query production metrics
- [ ] No query errors (data may be 0/empty initially)
- [ ] Time range set appropriately

#### Verify Alert Rules
```bash
# Check alert rules status
curl -s http://localhost:9090/api/v1/rules | jq '.data.groups[] | select(.name | contains("rfc_060")) | {name: .name, rules: [.rules[] | {alert: .name, state: .state}]}'

# Check for any alerts currently firing
curl -s http://localhost:9090/api/v1/alerts | jq '.data.alerts[] | select(.labels.rfc == "060") | {alert: .labels.alertname, state: .state, value: .value}'
```

**Alert Rules Checklist**:
- [ ] All 9 RFC-060 rules loaded
- [ ] Rules evaluating (state: "inactive" is OK)
- [ ] No evaluation errors
- [ ] No alerts firing (expected if no production data yet)

### Post-Deployment Validation

#### Generate Production Test Data

**Option 1: Run Real Workflow** (Recommended if safe)
```bash
# Use RSOLV-action in production with executable_tests=true
# Only if you have a test repository appropriate for production
```

**Option 2: Submit Synthetic Test Data** (Lower risk)
```bash
# Get production API key
PROD_API_KEY=$(kubectl get secret -n rsolv-production rsolv-secrets -o jsonpath='{.data.DEMO_API_KEY}' | base64 -d)

# Submit test validation
curl -X POST https://rsolv.dev/api/v1/phases/store \
  -H "Content-Type: application/json" \
  -H "x-api-key: $PROD_API_KEY" \
  -d '{
    "phase": "validation",
    "repo": "RSOLV-dev/test-repo",
    "issue_number": 999,
    "commit_sha": "test123",
    "data": {
      "validated": true,
      "language": "javascript",
      "framework": "express",
      "tests_generated": 3,
      "tests_passed": 3,
      "tests_failed": 0
    }
  }'

# Submit test mitigation
curl -X POST https://rsolv.dev/api/v1/phases/store \
  -H "Content-Type: application/json" \
  -H "x-api-key: $PROD_API_KEY" \
  -d '{
    "phase": "mitigation",
    "repo": "RSOLV-dev/test-repo",
    "issue_number": 999,
    "commit_sha": "test123",
    "data": {
      "pr_url": "https://github.com/test/pull/999",
      "pr_number": 999,
      "files_changed": 1,
      "trust_score": 95,
      "language": "javascript",
      "framework": "express"
    }
  }'
```

#### Verify Production Metrics
```bash
# Wait for Prometheus to scrape (15 seconds)
sleep 20

# Check validation metrics
curl -s 'http://localhost:9090/api/v1/query?query=rsolv_validation_executions_total{environment="production"}' | jq '.data.result'

# Check mitigation metrics
curl -s 'http://localhost:9090/api/v1/query?query=rsolv_mitigation_executions_total{environment="production"}' | jq '.data.result'

# Check trust scores
curl -s 'http://localhost:9090/api/v1/query?query=rsolv_mitigation_trust_score_value_sum{environment="production"}' | jq '.data.result'
```

**Metrics Verification**:
- [ ] Validation counter incremented
- [ ] Mitigation counter incremented
- [ ] Trust score recorded
- [ ] All labels present (repo, language, framework, environment)
- [ ] Environment label shows "production"
- [ ] Metrics visible in Grafana dashboard

#### Final Smoke Test Checklist

**Application Health**:
- [ ] Website loads: https://rsolv.dev
- [ ] API responds: https://rsolv.dev/api/health
- [ ] Metrics endpoint works: https://rsolv.dev/metrics
- [ ] No errors in application logs
- [ ] Database queries working
- [ ] All services connected (Postgres, Redis, etc.)

**Observability**:
- [ ] Prometheus scraping production successfully
- [ ] RFC-060 metrics visible in Prometheus
- [ ] Grafana dashboard shows production data
- [ ] Alert rules evaluating correctly
- [ ] No monitoring gaps

**Performance**:
- [ ] Response times normal (<2s for /health)
- [ ] No memory leaks (check pod memory usage)
- [ ] No CPU spikes (check pod CPU usage)
- [ ] Metrics endpoint response <1s

### Rollback Plan

#### If Deployment Fails

**Immediate Rollback**:
```bash
# Rollback to previous deployment
kubectl rollout undo deployment/rsolv-platform -n rsolv-production

# Verify rollback succeeded
kubectl rollout status deployment/rsolv-platform -n rsolv-production

# Check pods
kubectl get pods -n rsolv-production -l app=rsolv-platform
```

**Restore from Backup**:
```bash
# If rollback doesn't work, restore from backup
kubectl apply -f /tmp/production-deployment-backup-$(date +%Y%m%d).yaml
kubectl apply -f /tmp/production-configmaps-backup-$(date +%Y%m%d).yaml
```

#### Rollback Triggers

Rollback immediately if:
- [ ] Pods in CrashLoopBackOff for >5 minutes
- [ ] Application throwing errors (>5% error rate)
- [ ] Database connection failures
- [ ] /health endpoint returning errors
- [ ] Metrics endpoint not responding
- [ ] Critical functionality broken

### Success Criteria

**Deployment Successful**:
- [ ] All pods running and healthy
- [ ] No errors in logs
- [ ] /health endpoint returning 200 OK
- [ ] /metrics endpoint returning Prometheus format
- [ ] RFC-060 metrics defined (counts may be 0)
- [ ] Prometheus scraping successfully
- [ ] Grafana dashboard accessible
- [ ] Alert rules loaded and evaluating
- [ ] No performance degradation
- [ ] Rollback plan documented

**Ready for Production Traffic**:
- [ ] All monitoring in place
- [ ] Team notified of deployment
- [ ] Documentation updated
- [ ] Known issues documented (if any)

### Post-Deployment Tasks

#### Immediate (Within 1 Hour)
- [ ] Monitor logs for errors: `kubectl logs -n rsolv-production -l app=rsolv-platform --tail=100 --follow`
- [ ] Watch Prometheus for anomalies
- [ ] Check Grafana dashboard every 15 minutes
- [ ] Verify no alerts firing
- [ ] Test one real RSOLV-action workflow (if safe)

#### Same Day
- [ ] Update deployment documentation
- [ ] Notify team of successful deployment
- [ ] Create incident response plan for RFC-060 issues
- [ ] Schedule team training on new dashboard
- [ ] Document any issues encountered

#### Within 1 Week
- [ ] Review 7 days of production metrics
- [ ] Tune alert thresholds based on real data
- [ ] Adjust histogram buckets if needed
- [ ] Optimize dashboard queries
- [ ] Gather team feedback on dashboard usability
- [ ] Plan Phase 6 improvements

## Deployment Timeline Estimate

| Phase | Duration | Notes |
|-------|----------|-------|
| Pre-deployment verification | 15 min | Review config, secrets, backups |
| Docker build | 5-10 min | Depends on build cache |
| Registry push | 2-5 min | Depends on network |
| Deployment update | 2-5 min | Rolling update |
| Health stabilization | 5-10 min | Wait for new pods to be healthy |
| Monitoring verification | 10-15 min | Check Prometheus, Grafana, alerts |
| Smoke testing | 10-15 min | Generate test data, verify metrics |
| **Total** | **50-75 min** | **~1 hour for careful deployment** |

## Team Communication

### Pre-Deployment Announcement
```
🚀 RFC-060 Phase 5.4 Production Deployment Starting

**What**: Deploying observability infrastructure for validation/mitigation metrics
**When**: [Timestamp]
**Impact**: No user-facing changes, metrics collection only
**Rollback**: Automated rollback available if needed
**Monitoring**: New Grafana dashboard will be available after deployment

**Action Required**: None
**Questions**: #engineering-ops
```

### Post-Deployment Announcement
```
✅ RFC-060 Phase 5.4 Production Deployment Complete

**Status**: Successful deployment at [timestamp]
**New Features**:
  - Validation & mitigation metrics now collected
  - Grafana dashboard: http://grafana.rsolv.dev/d/rfc-060-validation
  - 9 new alert rules active

**Verification**:
  - All pods healthy ✅
  - Metrics flowing to Prometheus ✅
  - Dashboard operational ✅
  - No alerts firing ✅

**Next Steps**:
  - Team training on dashboard (scheduled [date])
  - Alert notification configuration (Phase 5.6)
  - Production monitoring begins

**Issues**: None reported
```

## Emergency Contacts

- **On-Call Engineer**: [Name/Contact]
- **Platform Team Lead**: [Name/Contact]
- **Database Admin**: [Name/Contact]
- **Incident Slack Channel**: #incidents
- **Deployment Slack Channel**: #deployments

## Additional Resources

- [RFC-060 Implementation Status](RFC-060-IMPLEMENTATION-STATUS.md)
- [Phase 5.5 Monitoring Complete](RFC-060-PHASE-5.5-MONITORING-COMPLETE.md)
- [Phase 5.3 Smoke Test](RFC-060-PHASE-5.3-SMOKE-TEST-COMPLETE.md)
- [Deployment Guide](rsolv-infrastructure/DEPLOYMENT.md)
- [Rollback Procedures](rsolv-infrastructure/ROLLBACK.md)
- [Incident Response](rsolv-infrastructure/INCIDENT-RESPONSE.md)

---

**Checklist Owner**: [Your Name]
**Deployment Date**: [To be filled]
**Deployment Time**: [To be filled]
**Deployment Engineer**: [To be filled]
**Approval**: [ ] Engineering Lead / [ ] CTO

**Post-Deployment Sign-Off**:
- [ ] Deployment successful
- [ ] All checks passed
- [ ] Team notified
- [ ] Documentation updated
- [ ] Monitoring confirmed

**Signature**: _________________ **Date**: _________
