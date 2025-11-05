# Billing System Monitoring Deployment Guide

**Date**: 2025-11-04
**RFC**: RFC-069 Friday
**Status**: Production Ready

## Overview

This document describes the complete monitoring and alerting setup for the RSOLV billing system (RFC-065, RFC-066, RFC-067, RFC-068).

## Monitoring Components

### 1. Metrics Collection (PromEx + BillingPlugin)

**File**: `lib/rsolv/prom_ex/billing_plugin.ex`

**Metrics Tracked**:
- **Subscription lifecycle**: Created, renewed, cancelled
- **Payment processing**: Success/failure rates, amounts, duration
- **Stripe webhooks**: Receipt rate, processing duration, failures
- **Usage tracking**: Fixes consumed, credit balance changes
- **Credit system**: Credits added, consumed, balances

**Telemetry Events**:
```elixir
# Subscription
:telemetry.execute([:rsolv, :billing, :subscription_created], %{amount: 4900, duration: 250}, %{customer_id: "cus_123", plan: "pro", status: "success"})

# Payment
:telemetry.execute([:rsolv, :billing, :payment_processed], %{amount_cents: 4900, duration: 1200}, %{customer_id: "cus_123", status: "success", payment_method: "card"})

# Webhook
:telemetry.execute([:rsolv, :billing, :stripe_webhook_received], %{duration: 45}, %{event_type: "invoice.paid", status: "success"})

# Usage
:telemetry.execute([:rsolv, :billing, :usage_tracked], %{quantity: 1}, %{customer_id: "cus_123", plan: "pro", resource_type: "fix"})

# Credits
:telemetry.execute([:rsolv, :billing, :credits_added], %{quantity: 60}, %{customer_id: "cus_123", reason: "billing_added"})
```

### 2. Grafana Dashboard

**File**: `priv/grafana_dashboards/billing_dashboard.json`

**Dashboard Panels**:
1. **Subscription Creation Rate** - Subscriptions/sec by plan
2. **Payment Success Rate** - Gauge (target: >95%)
3. **Revenue by Plan** - 24h pie chart
4. **Payment Processing Duration** - p95 latency by payment method
5. **Usage Tracking** - Fixes consumed by plan
6. **Customer Conversion Funnel** - Signups → Billing → Pro
7. **Failed Payments by Reason** - Top 10 failure codes
8. **Subscription Cancellation Rate** - % of creations
9. **Active Subscriptions by Plan** - Time series
10. **Credit System Overview** - Added vs consumed

**Access**:
- URL: https://grafana.rsolv.dev/d/billing-metrics
- Username: admin
- Password: RSolvMonitor123!

### 3. Prometheus Alerts

**File**: `config/prometheus/billing-alerts.yml`

**Alert Categories**:

#### Payment Alerts
- `BillingPaymentFailureRateHigh` - >10% failures (warning)
- `BillingPaymentFailureRateCritical` - >25% failures (critical)

#### Webhook Alerts
- `StripeWebhookFailureRateHigh` - >10% failures (warning)
- `StripeWebhookProcessingDurationHigh` - p95 > 1s (warning)
- `StripeWebhooksStalled` - No webhooks for 6h (info)

#### Subscription Alerts
- `SubscriptionCancellationRateHigh` - >10% cancellation rate (warning)


#### Business Alerts
- `BillingCreditGrantAnomalyDetected` - p99 > 1000 credits (info)

### 4. AlertManager Configuration

**File**: `monitoring/alertmanager-config-webhook.yaml`

**Alert Routing**:
```yaml
# Billing critical → admin@rsolv.dev, billing-oncall@rsolv.dev
# Billing warnings → admin@rsolv.dev, alerts@rsolv.dev
# Billing info → alerts@rsolv.dev
```

**Alert Channels** (configured):
- ✅ Email (Postmark)
- 🔜 PagerDuty (TODO)
- 🔜 Slack (TODO)

### 5. Error Tracking

**Prometheus Metrics**: Payment, webhook, and invoice failure tracking

**Application Logging**: Standard Logger with structured metadata

## Deployment Steps

### Step 1: Deploy Code Changes

**Files Changed**:
- `lib/rsolv/prom_ex.ex` - Added BillingPlugin and dashboard
- `lib/rsolv/prom_ex/billing_plugin.ex` - Already exists, enhanced with webhooks
- `lib/rsolv_web/controllers/webhook_controller.ex` - Added telemetry events
- `priv/grafana_dashboards/billing_dashboard.json` - Moved from config/monitoring/

**Deployment**:
```bash
# Build and push image
cd /var/tmp/vibe-kanban/worktrees/76ff-week-5-set-up-pr
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
TAG="billing-monitoring-${TIMESTAMP}"

docker build -t ghcr.io/rsolv-dev/rsolv-platform:${TAG} .
docker push ghcr.io/rsolv-dev/rsolv-platform:${TAG}

# Deploy to staging first
kubectl set image deployment/staging-rsolv-platform \
  rsolv-platform=ghcr.io/rsolv-dev/rsolv-platform:${TAG} \
  -n rsolv-staging

# Monitor rollout
kubectl rollout status deployment/staging-rsolv-platform -n rsolv-staging

# Deploy to production (after staging verification)
kubectl set image deployment/rsolv-platform \
  rsolv-platform=ghcr.io/rsolv-dev/rsolv-platform:${TAG} \
  -n rsolv-production

kubectl rollout status deployment/rsolv-platform -n rsolv-production
```

### Step 2: Deploy Prometheus Alert Rules

**Update Prometheus ConfigMap**:
```bash
# Add billing-alerts.yml to Prometheus ConfigMap
kubectl create configmap prometheus-config \
  --from-file=prometheus.yml=monitoring/prometheus-config.yaml \
  --from-file=rfc-060-alerts.yml=config/prometheus/rfc-060-alerts.yml \
  --from-file=billing-alerts.yml=config/prometheus/billing-alerts.yml \
  -n monitoring \
  --dry-run=client -o yaml | kubectl apply -f -

# Reload Prometheus configuration
kubectl exec -n monitoring deployment/prometheus -- kill -HUP 1
```

### Step 3: Update AlertManager Configuration

**Deploy updated AlertManager config**:
```bash
# Apply updated ConfigMap
kubectl apply -f monitoring/alertmanager-config-webhook.yaml

# Reload AlertManager
kubectl exec -n monitoring deployment/alertmanager -- kill -HUP 1
```

### Step 4: Import Grafana Dashboard

**Option A: Via API** (recommended):
```bash
# Get Grafana API token (admin user)
GRAFANA_TOKEN="<your-grafana-api-token>"

# Import dashboard
curl -X POST https://grafana.rsolv.dev/api/dashboards/db \
  -H "Authorization: Bearer ${GRAFANA_TOKEN}" \
  -H "Content-Type: application/json" \
  -d @priv/grafana_dashboards/billing_dashboard.json
```

**Option B: Via UI**:
1. Login to https://grafana.rsolv.dev
2. Click "+" → "Import"
3. Upload `priv/grafana_dashboards/billing_dashboard.json`
4. Select "Prometheus" as datasource
5. Click "Import"


## Verification Steps

### 1. Verify Metrics Collection

```bash
# Check if metrics are being exported
curl http://localhost:9568/metrics | grep rsolv_billing

# Expected metrics:
# rsolv_billing_subscription_created_total
# rsolv_billing_payment_processed_total
# rsolv_billing_stripe_webhook_received_total
# rsolv_billing_usage_tracked_total
# rsolv_billing_credits_added_total
```

### 2. Verify Dashboard

1. Login to Grafana: https://grafana.rsolv.dev
2. Navigate to billing metrics dashboard
3. Verify panels are loading data
4. Check for "No data" warnings (may be normal if no billing activity yet)

### 3. Verify Alerts

**Check Prometheus alerts**:
```bash
# Port-forward to Prometheus
kubectl port-forward -n monitoring deployment/prometheus 9090:9090

# Open http://localhost:9090/alerts
# Verify billing alerts are loaded and in "inactive" state
```

**Test alert delivery**:
```bash
# Option 1: Trigger test alert manually
# Port-forward to AlertManager
kubectl port-forward -n monitoring deployment/alertmanager 9093:9093

# Send test alert
curl -X POST http://localhost:9093/api/v1/alerts -d '[{
  "labels": {
    "alertname": "BillingTestAlert",
    "component": "billing",
    "severity": "info"
  },
  "annotations": {
    "summary": "Test billing alert"
  }
}]'

# Check email delivery to alerts@rsolv.dev
```

**Option 2: Use Prometheus amtool**:
```bash
kubectl exec -n monitoring deployment/alertmanager -- \
  amtool alert add BillingTestAlert \
  --alertmanager.url=http://localhost:9093 \
  component=billing severity=info
```


## Monitoring Checklist

After deployment, verify:

- [ ] Prometheus is scraping billing metrics
- [ ] Grafana dashboard is accessible and showing data
- [ ] All 7 alert rules are loaded in Prometheus
- [ ] AlertManager routing is configured for billing alerts
- [ ] Test email alert delivered successfully
- [ ] Metrics are being emitted from webhook controller
- [ ] BillingPlugin is registered in PromEx configuration
- [ ] Dashboard panels are not showing "No data" errors
- [ ] Alert thresholds are appropriate for production

## Runbooks

See:
- [Billing Payment Failures Runbook](./BILLING-PAYMENT-FAILURES-RUNBOOK.md)
- [Stripe Webhook Failures Runbook](./STRIPE-WEBHOOK-FAILURES-RUNBOOK.md)
- [Billing Critical Alert Runbook](./BILLING-CRITICAL-ALERT-RUNBOOK.md)

## Troubleshooting

### Issue: Dashboard shows "No data"

**Cause**: Metrics not being scraped or no billing activity yet

**Solution**:
```bash
# Check if metrics endpoint is accessible
kubectl exec -n rsolv-production deployment/rsolv-platform -- \
  curl localhost:9568/metrics | grep rsolv_billing

# Check Prometheus scrape targets
# Port-forward to Prometheus
kubectl port-forward -n monitoring deployment/prometheus 9090:9090
# Open http://localhost:9090/targets
# Verify rsolv-platform targets are "UP"
```

### Issue: Alerts not firing

**Cause**: Alert rules not loaded or thresholds not met

**Solution**:
```bash
# Check Prometheus logs
kubectl logs -n monitoring deployment/prometheus | grep -i error

# Reload configuration
kubectl exec -n monitoring deployment/prometheus -- kill -HUP 1

# Verify rules are loaded
# Port-forward and visit http://localhost:9090/rules
```

### Issue: Email alerts not delivered

**Cause**: Postmark API key invalid or email address bounced

**Solution**:
```bash
# Check AlertManager logs
kubectl logs -n monitoring deployment/alertmanager | grep -i email

# Verify Postmark API key
kubectl get configmap -n monitoring alertmanager-config -o yaml | grep smtp_auth

# Test Postmark directly
curl -X POST "https://api.postmarkapp.com/email" \
  -H "X-Postmark-Server-Token: <API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "From": "alerts@rsolv.dev",
    "To": "admin@rsolv.dev",
    "Subject": "Test",
    "TextBody": "Test email"
  }'
```

### Issue: Webhook metrics not appearing

**Cause**: Telemetry events not being emitted or plugin not registered

**Solution**:
```bash
# Verify BillingPlugin is registered
kubectl exec -n rsolv-production deployment/rsolv-platform -- \
  /app/bin/rsolv eval 'Rsolv.PromEx.plugins() |> Enum.find(&(&1 == Rsolv.PromEx.BillingPlugin))'

# Check application logs for telemetry errors
kubectl logs -n rsolv-production deployment/rsolv-platform | grep -i telemetry

# Test webhook endpoint manually
curl -X POST https://api.rsolv.dev/api/webhooks/stripe \
  -H "stripe-signature: t=invalid,v1=invalid" \
  -d '{}'
# Should see webhook failure metric increment
```

## Alert Testing Procedure

Before relying on alerts in production, test each alert:

### 1. BillingPaymentFailureRateHigh

**Simulate**: Process multiple failed payments

```bash
# Option: Use Stripe test mode with declined cards
# Test card: 4000 0000 0000 0002 (card_declined)

curl -X POST https://api.rsolv.dev/api/v1/billing/payment-methods \
  -H "Authorization: Bearer <test-api-key>" \
  -d '{"stripe_payment_method_id": "pm_card_declined"}'

# Repeat 10+ times to trigger >10% failure rate
```

**Expected**: Alert fires after 15 minutes, email sent to admin@rsolv.dev and alerts@rsolv.dev

### 2. StripeWebhookFailureRateHigh

**Simulate**: Send invalid webhook signatures

```bash
for i in {1..10}; do
  curl -X POST https://api.rsolv.dev/api/webhooks/stripe \
    -H "stripe-signature: t=$(date +%s),v1=invalid_signature" \
    -d '{"id": "evt_test", "type": "test", "data": {}}'
done
```

**Expected**: Alert fires after 15 minutes

### 3. StripeWebhookProcessingDurationHigh

**Simulate**: Add artificial delay in webhook processing (not recommended for prod)

**Alternative**: Monitor naturally during high load

### 4. SubscriptionCancellationRateHigh

**Simulate**: Cancel multiple subscriptions

```bash
# Use Stripe dashboard or API to cancel test subscriptions
```

**Expected**: Alert fires after 1 hour if >10% cancellation rate

## On-Call Rotation

**Current Rotation** (RFC-069):
- Primary: admin@rsolv.dev
- Backup: billing-oncall@rsolv.dev

**Response Times**:
- **Critical** (severity: critical): 15 minutes
- **Warning** (severity: warning): 1 hour
- **Info** (severity: info): Next business day

## Metrics Retention

**Prometheus**: 15 days (default)
**Grafana**: Query only (no storage)
**Sentry**: 90 days (default)

## Future Enhancements

- [ ] PagerDuty integration for critical billing alerts
- [ ] Slack integration for billing warnings
- [ ] Custom billing health check endpoint
- [ ] Automated weekly billing health reports
- [ ] Customer-facing billing status page
- [ ] Billing audit log dashboard
- [ ] Stripe API rate limit monitoring

---

**References**:
- RFC-069: Integration Week Production Readiness
- RFC-068: Billing Testing Infrastructure
- RFC-066: Stripe Billing Integration
- RFC-065: Automated Customer Provisioning
