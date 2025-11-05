# Week 5: API Performance Monitoring Deployment Guide

**Created:** 2025-11-04
**Task:** VK `651a3ef1` - [Week 5] Establish baseline API performance metrics and alerting

## Overview

This document provides step-by-step instructions for deploying the new API performance monitoring, database query monitoring, and webhook processing alerting to the production Kubernetes cluster.

**What's Being Deployed:**
- New Prometheus alert rules for API performance, database queries, and webhook processing
- Updated AlertManager configuration with new alert routing
- New Grafana dashboard for API performance baseline visualization

**Impact:**
- ✅ **Zero downtime** - No service interruption
- ✅ **No code changes** - Configuration only
- ✅ **Existing metrics** - Uses already-collected PromEx metrics
- ⚠️ **Email volume** - May generate alerts if thresholds are breached (expected during initial tuning)

## Prerequisites

**Access Required:**
- Kubernetes cluster access with `kubectl` configured
- Grafana admin credentials for dashboard upload
- SSH access to Kubernetes control plane (for Prometheus/AlertManager pods)

**Verify Current State:**
```bash
# Check Prometheus is running
kubectl -n monitoring get pods -l app=prometheus

# Check AlertManager is running
kubectl -n monitoring get pods -l app=alertmanager

# Check Grafana is accessible
curl -I https://grafana.rsolv.dev

# Check metrics endpoint is working
curl -I https://rsolv.dev/metrics
```

Expected: All pods Running, Grafana returns 200 OK, metrics endpoint returns 200 OK.

## Deployment Steps

### Step 1: Update AlertManager Configuration

**Purpose:** Add routing rules for API, database, and webhook alerts.

```bash
# Navigate to repository root
cd /var/tmp/vibe-kanban/worktrees/0fc2-week-5-establish

# Review the updated AlertManager config
cat monitoring/alertmanager-config-webhook.yaml

# Apply the updated configuration
kubectl apply -f monitoring/alertmanager-config-webhook.yaml

# Verify ConfigMap was updated
kubectl -n monitoring get configmap alertmanager-config -o yaml

# Reload AlertManager to pick up new config (without restarting)
kubectl -n monitoring exec -it deployment/alertmanager -- \
  wget --post-data="" http://localhost:9093/-/reload
```

**Verification:**
```bash
# Check AlertManager logs for successful reload
kubectl -n monitoring logs deployment/alertmanager --tail=50

# Expected: "Completed loading of configuration file" without errors
```

### Step 2: Add Prometheus Alert Rules

**Purpose:** Load new alert rules for API performance monitoring.

```bash
# Create ConfigMap for new alert rules
kubectl create configmap api-performance-alerts \
  --from-file=api-performance-alerts.yml=config/prometheus/api-performance-alerts.yml \
  -n monitoring \
  --dry-run=client -o yaml | kubectl apply -f -

# Update Prometheus configuration to load the new rules
# This requires editing the Prometheus ConfigMap to reference the new rules file

# Get current Prometheus config
kubectl -n monitoring get configmap prometheus-config -o yaml > /tmp/prometheus-config-backup.yaml

# Add the new rule file to the configuration
# Edit the ConfigMap to include:
#   rule_files:
#     - /etc/prometheus/rules/*.yml
#     - /etc/prometheus/api-performance-alerts/*.yml

# If using file-based config, mount the ConfigMap as a volume in Prometheus deployment
kubectl -n monitoring edit deployment prometheus

# Add volume:
#   - name: api-performance-alerts
#     configMap:
#       name: api-performance-alerts
#
# Add volumeMount:
#   - name: api-performance-alerts
#     mountPath: /etc/prometheus/api-performance-alerts

# Reload Prometheus configuration
kubectl -n monitoring exec -it deployment/prometheus -- \
  wget --post-data="" http://localhost:9090/-/reload
```

**Alternative (Simpler) Approach:**

If Prometheus is configured to load all rules from a single ConfigMap:

```bash
# Get the existing rules ConfigMap
kubectl -n monitoring get configmap prometheus-rules -o yaml > /tmp/prometheus-rules-backup.yaml

# Add the new alert rules to the existing ConfigMap
kubectl -n monitoring create configmap prometheus-rules \
  --from-file=billing-alerts.yml=config/prometheus/billing-alerts.yml \
  --from-file=rfc-060-alerts.yml=config/prometheus/rfc-060-alerts.yml \
  --from-file=api-performance-alerts.yml=config/prometheus/api-performance-alerts.yml \
  --dry-run=client -o yaml | kubectl apply -f -

# Reload Prometheus
kubectl -n monitoring exec -it deployment/prometheus -- \
  curl -X POST http://localhost:9090/-/reload
```

**Verification:**
```bash
# Check Prometheus logs for successful reload
kubectl -n monitoring logs deployment/prometheus --tail=50

# Access Prometheus UI and verify rules are loaded
# Navigate to: https://prometheus.rsolv.dev/rules
# (or kubectl port-forward if not exposed)
kubectl -n monitoring port-forward svc/prometheus 9090:9090

# Open browser: http://localhost:9090/rules
# Verify "api_performance" group is listed with 15 rules
```

### Step 3: Upload Grafana Dashboard

**Purpose:** Add the API Performance Baseline dashboard to Grafana.

**Option A: Manual Upload (Recommended for first deployment)**

```bash
# Copy dashboard JSON to your local machine if working remotely
scp /var/tmp/vibe-kanban/worktrees/0fc2-week-5-establish/grafana_dashboards/api-performance-baseline.json \
  user@local-machine:/tmp/

# Open Grafana UI
# Navigate to: https://grafana.rsolv.dev

# Manual steps:
# 1. Login with admin credentials
# 2. Click "+" → "Import dashboard"
# 3. Upload api-performance-baseline.json
# 4. Select "prometheus" as the data source
# 5. Click "Import"
# 6. Verify dashboard loads with panels showing data
```

**Option B: Automated Upload via API**

```bash
# Set Grafana credentials
export GRAFANA_URL="https://grafana.rsolv.dev"
export GRAFANA_API_KEY="<your-grafana-api-key>"  # Or use basic auth

# Upload dashboard
curl -X POST "${GRAFANA_URL}/api/dashboards/db" \
  -H "Authorization: Bearer ${GRAFANA_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @grafana_dashboards/api-performance-baseline.json

# Expected response: {"id":..., "uid":"api-performance-baseline", "status":"success"}
```

**Option C: Provisioning (For automated deployments)**

If Grafana uses dashboard provisioning:

```bash
# Copy dashboard to Grafana provisioning directory
kubectl -n monitoring cp \
  grafana_dashboards/api-performance-baseline.json \
  grafana-pod-name:/etc/grafana/provisioning/dashboards/api-performance-baseline.json

# Grafana will auto-reload dashboards from provisioning directory
# Wait ~30 seconds and refresh Grafana UI
```

**Verification:**
```bash
# Access the dashboard
# URL: https://grafana.rsolv.dev/d/api-performance-baseline

# Verify all panels are showing data:
# - API Error Rate (5xx) - should show 0% or low value
# - API P95 Latency - should show < 1000ms if traffic exists
# - Database P95 Query Latency - should show < 100ms
# - API Request Rate - should show current req/s
# - API Requests by Status Code - should show 200/400/500 series
# - API Response Time Percentiles - should show P50/P95/P99 lines
# - P95 Latency by Critical Endpoint - filtered by key endpoints
# - Database Query Latency Percentiles - P50/P95/P99
# - Database Connection Pool Utilization - should show < 80%
# - Webhook Processing P95 Latency - may be empty if no webhooks yet
```

## Post-Deployment Verification

### 1. Test Alert Routing

**Send a test alert to verify email delivery:**

```bash
# Access AlertManager pod
kubectl -n monitoring exec -it deployment/alertmanager -- sh

# Inside the pod, send a test alert
cat <<EOF | wget --post-data=@- http://localhost:9093/api/v1/alerts -O-
[
  {
    "labels": {
      "alertname": "TestAPIAlert",
      "severity": "warning",
      "component": "api"
    },
    "annotations": {
      "summary": "Test API alert for Week 5 monitoring deployment",
      "description": "This is a test alert to verify email routing."
    },
    "startsAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  }
]
EOF
```

**Expected:**
- Email received at admin@rsolv.dev and alerts@rsolv.dev
- Subject: "⚠️  API Performance Warning: TestAPIAlert"
- Content includes summary and description

**Resolve the test alert:**
```bash
# Send an end time to resolve the alert
cat <<EOF | wget --post-data=@- http://localhost:9093/api/v1/alerts -O-
[
  {
    "labels": {
      "alertname": "TestAPIAlert",
      "severity": "warning",
      "component": "api"
    },
    "endsAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  }
]
EOF
```

### 2. Monitor for Real Alerts

**Check Prometheus for pending/firing alerts:**

```bash
# Port-forward Prometheus UI
kubectl -n monitoring port-forward svc/prometheus 9090:9090

# Open browser: http://localhost:9090/alerts
# Check if any new alerts are in "Pending" or "Firing" state
```

**If alerts are firing:**
- **APIErrorRateHigh** - Check application logs for 5xx errors
- **APIP95LatencyHigh** - Review slow endpoints and database queries
- **DatabaseQueryLatencyHigh** - Check slow query log and connection pool
- **WebhookProcessingLatencyHigh** - Review Oban worker queue backlog

**Adjust thresholds if needed:**

If alerts are firing but traffic is normal, thresholds may need tuning:

```bash
# Edit alert rules
kubectl -n monitoring edit configmap prometheus-rules

# Adjust threshold values in the `expr:` field
# Example: Change > 1000 to > 2000 for APIP95LatencyHigh

# Reload Prometheus
kubectl -n monitoring exec -it deployment/prometheus -- \
  curl -X POST http://localhost:9090/-/reload
```

### 3. Verify Metrics Collection

**Check that all expected metrics are being scraped:**

```bash
# Query Prometheus for key metrics
kubectl -n monitoring port-forward svc/prometheus 9090:9090

# Open Prometheus UI: http://localhost:9090/graph

# Run these PromQL queries to verify data:

# 1. API request count
phoenix_http_request_duration_milliseconds_count

# 2. API P95 latency
histogram_quantile(0.95, sum by (le) (rate(phoenix_http_request_duration_milliseconds_bucket[5m])))

# 3. Database query latency
histogram_quantile(0.95, sum by (le) (rate(rsolv_prom_ex_ecto_query_duration_milliseconds_bucket[5m])))

# 4. Webhook processing
rsolv_billing_stripe_webhook_received_total

# All queries should return data (not "no data")
```

## Monitoring the Baseline

### First 24 Hours

**Objectives:**
1. Ensure no false-positive alerts
2. Validate threshold values match production traffic
3. Observe actual P95 latency under normal load
4. Document any threshold adjustments

**Monitoring Checklist:**

- [ ] Check Grafana dashboard hourly for first 6 hours
- [ ] Review any alerts that fire (expected or unexpected?)
- [ ] Monitor email for alert notifications
- [ ] Compare actual P95 latency vs. thresholds
- [ ] Check error rate remains < 1%
- [ ] Verify database connection pool usage < 80%

**Record Observations:**

Update `CUSTOMER-TRACTION-TRACKING.md` with actual baseline values:

```markdown
## Observed Baseline Values (First 24 Hours)

**API Performance (2025-11-04 to 2025-11-05):**
- Average P50 latency: ___ ms
- Average P95 latency: ___ ms
- Peak P95 latency: ___ ms
- Error rate (5xx): ___%
- Request rate: ___ req/min

**Database Performance:**
- Average P95 query latency: ___ ms
- Peak P95 query latency: ___ ms
- Average connection pool usage: ___%

**Webhook Processing:**
- Average P95 latency: ___ ms
- Processing success rate: ___%
```

### Threshold Tuning

If thresholds need adjustment after observing actual traffic:

1. **Document the reason** - Why is the current threshold too high/low?
2. **Update alert rules** - Edit `config/prometheus/api-performance-alerts.yml`
3. **Update tracking doc** - Update thresholds in `CUSTOMER-TRACTION-TRACKING.md`
4. **Redeploy** - Apply updated ConfigMap and reload Prometheus
5. **Monitor** - Verify new thresholds work as expected

**Common Adjustments:**

| Alert | Common Issue | Recommended Action |
|-------|--------------|-------------------|
| APIP95LatencyHigh | Firing during normal traffic | Increase from 1000ms to actual P95 + 20% buffer |
| DatabaseQueryLatencyHigh | Firing for complex queries | Increase from 100ms to actual P95 + 30% buffer |
| APIRequestRateAnomalyLow | Firing overnight (low traffic) | Adjust time window or add hour() filter |

## Rollback Procedure

If issues arise, follow these steps to rollback:

### Rollback AlertManager Config

```bash
# Restore previous AlertManager config
kubectl apply -f /tmp/alertmanager-config-backup.yaml

# Reload AlertManager
kubectl -n monitoring exec -it deployment/alertmanager -- \
  wget --post-data="" http://localhost:9093/-/reload
```

### Rollback Prometheus Alert Rules

```bash
# Remove new alert rules
kubectl -n monitoring delete configmap api-performance-alerts

# Or restore previous rules ConfigMap
kubectl apply -f /tmp/prometheus-rules-backup.yaml

# Reload Prometheus
kubectl -n monitoring exec -it deployment/prometheus -- \
  curl -X POST http://localhost:9090/-/reload
```

### Remove Grafana Dashboard

```bash
# Via Grafana UI:
# 1. Navigate to dashboard: https://grafana.rsolv.dev/d/api-performance-baseline
# 2. Click "Dashboard settings" (gear icon)
# 3. Click "Delete dashboard"

# Via API:
curl -X DELETE "${GRAFANA_URL}/api/dashboards/uid/api-performance-baseline" \
  -H "Authorization: Bearer ${GRAFANA_API_KEY}"
```

## Troubleshooting

### Alerts Not Firing

**Symptom:** No alerts in Prometheus UI, no emails received

**Check:**
1. Alert rules loaded in Prometheus: http://localhost:9090/rules
2. AlertManager is receiving alerts: http://localhost:9093/#/alerts
3. AlertManager config has correct email settings
4. SMTP credentials are valid (check AlertManager logs)

**Debug:**
```bash
# Check Prometheus alert evaluation
kubectl -n monitoring logs deployment/prometheus | grep -i "alert"

# Check AlertManager routing
kubectl -n monitoring logs deployment/alertmanager | grep -i "route"

# Test SMTP connectivity
kubectl -n monitoring exec -it deployment/alertmanager -- \
  nc -zv smtp.postmarkapp.com 587
```

### Metrics Not Showing in Dashboard

**Symptom:** Grafana panels show "No Data"

**Check:**
1. Metrics endpoint is accessible: `curl https://rsolv.dev/metrics`
2. Prometheus is scraping the endpoint: http://localhost:9090/targets
3. Metrics exist in Prometheus: Run PromQL query in Prometheus UI
4. Grafana data source is configured correctly

**Debug:**
```bash
# Check Prometheus scrape config
kubectl -n monitoring get configmap prometheus-config -o yaml | grep -A 10 "rsolv-platform"

# Check Prometheus scrape status
# Navigate to: http://localhost:9090/targets
# Find "rsolv-platform" target, verify it's "UP"

# If target is DOWN, check metrics endpoint
curl -v https://rsolv.dev/metrics
```

### High Alert Volume

**Symptom:** Too many alert emails, alert fatigue

**Solutions:**
1. **Increase `group_wait`** - Delay before sending first alert (default: 10s-1m)
2. **Increase `repeat_interval`** - Time before resending alert (default: 2-12h)
3. **Adjust thresholds** - Make thresholds less sensitive
4. **Add inhibition rules** - Suppress related alerts

**Example:**
```yaml
# In alertmanager-config-webhook.yaml
routes:
  - match:
      component: api
      severity: warning
    receiver: 'api-warnings'
    group_wait: 5m        # Wait 5 min before sending (was 1m)
    repeat_interval: 12h  # Resend every 12h (was 6h)
```

## Files Modified

**New Files:**
- `config/prometheus/api-performance-alerts.yml` - 15 new alert rules
- `grafana_dashboards/api-performance-baseline.json` - Grafana dashboard
- `WEEK5-MONITORING-DEPLOYMENT.md` - This deployment guide

**Modified Files:**
- `monitoring/alertmanager-config-webhook.yaml` - Added API/database/webhook alert routing
- `projects/go-to-market-2025-10/CUSTOMER-TRACTION-TRACKING.md` - Documented baselines

## Success Criteria

**Deployment is successful when:**
- ✅ All alert rules are loaded in Prometheus (15 rules in `api_performance` group)
- ✅ AlertManager shows updated routing configuration
- ✅ Grafana dashboard is accessible and shows data
- ✅ Test alert email is received successfully
- ✅ No false-positive alerts during first 6 hours
- ✅ Baseline metrics documented in tracking doc

## Next Steps After Deployment

1. **Monitor for 24-48 hours** - Observe actual traffic patterns
2. **Tune thresholds** - Adjust based on observed baselines
3. **Document runbooks** - Create alert response procedures
4. **Set up on-call rotation** - Define who responds to alerts
5. **Plan Slack integration** - Add Slack notifications for high-severity alerts
6. **Weekly review** - Check alert history and adjust as needed

## Support

**Questions or Issues:**
- Check Prometheus logs: `kubectl -n monitoring logs deployment/prometheus`
- Check AlertManager logs: `kubectl -n monitoring logs deployment/alertmanager`
- Review existing monitoring setup: `docs/MONITORING-OBSERVABILITY-SETUP.md`
- Contact: VK task `651a3ef1` - Week 5 monitoring setup

---

**Deployment Completed:** _[Date]_
**Deployed By:** _[Name]_
**Notes:** _[Any deployment-specific notes or observations]_
