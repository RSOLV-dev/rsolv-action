# Billing Monitoring Consolidation Review

**Date**: 2025-11-04
**Reviewer Feedback**: User identified redundancies and questioned Sentry

## Changes Made

### 1. Removed Redundant Infrastructure Alerts ✅

**Removed 3 alerts** that were app-wide concerns, not billing-specific:

#### ❌ `BillingDatabaseConnectionPoolHigh`
**Why Removed**: Database connection pool is shared across the entire application. If it's at 80%, this affects all features (validation, API, webhooks), not just billing. This should be a **general platform alert**, not a billing alert.

#### ❌ `BillingAppMemoryUsageHigh`
**Why Removed**: Memory usage is per-pod, not per-feature. High memory affects the entire application, not just billing operations. This should be a **general platform alert**.

#### ❌ `BillingRateLimitHitRateHigh`
**Why Removed**: While this filtered for billing endpoints, rate limiting is a platform-wide concern. If we need endpoint-specific rate limit alerts, they should be in a general API monitoring file, not billing-specific.

**Result**: Reduced from **10 alerts to 7 alerts**, all truly billing-domain specific.

### 2. Sentry - Clarified as Optional ❌ Not Configured

**Original Status**: Marked as "✅ Configured"
**Actual Status**: Configuration exists but is **inactive** (no SENTRY_DSN set)

**What Changed**:
- Removed Sentry from "completed" checklist items
- Marked as "Optional" in documentation
- Kept the conditional config in `config/runtime.exs` (harmless, future-ready)
- Removed Sentry testing/verification from deployment steps

**Clarification**: The code has Sentry *support* but Sentry is not *active* unless you set `SENTRY_DSN` environment variable. Since you don't have a Sentry account, this is not providing error tracking.

### 3. Dashboard - No Redundancy ✅

**Finding**: The billing dashboard (`priv/grafana_dashboards/billing_dashboard.json`) already existed at `config/monitoring/billing_dashboard.json`.

**Action Taken**: Moved it to the PromEx conventional location and added to PromEx configuration. This is not redundancy, just organization.

### 4. Metrics - No Redundancy ✅

**CustomerOnboardingPlugin vs BillingPlugin**:
- **CustomerOnboardingPlugin**: Tracks initial signup flow (one-time)
- **BillingPlugin**: Tracks ongoing billing operations (recurring)

These cover **different lifecycle stages** and don't overlap.

## Final Monitoring Configuration

### Metrics (PromEx Plugins)
- ✅ **BillingPlugin**: Subscriptions, payments, webhooks, usage, credits
- ✅ **CustomerOnboardingPlugin**: Initial signup flow
- ✅ **ValidationPlugin**: RFC-060 validation metrics
- ✅ Built-in: Application, BEAM, Phoenix, Ecto, LiveView

### Alerts (7 Total)

#### Payment Alerts (2)
1. `BillingPaymentFailureRateHigh` - >10% failures for 15min (warning)
2. `BillingPaymentFailureRateCritical` - >25% failures for 10min (critical)

#### Webhook Alerts (3)
3. `StripeWebhookFailureRateHigh` - >10% failures for 15min (warning)
4. `StripeWebhookProcessingDurationHigh` - p95 >1s for 20min (warning)
5. `StripeWebhooksStalled` - No webhooks for 6h (info)

#### Subscription Alerts (1)
6. `SubscriptionCancellationRateHigh` - >10% cancellation rate for 1h (warning)

#### Business Alerts (1)
7. `BillingCreditGrantAnomalyDetected` - p99 >1000 credits (info)

### Dashboards
- ✅ **Billing Dashboard**: 10 panels covering billing operations
- ✅ **RFC-060 Validation Dashboard**: Validation/mitigation metrics
- ✅ **False Positive Cache Dashboard**: Cache performance (prod/staging)
- ✅ **PromEx Built-in Dashboards**: Application, BEAM, Phoenix, Ecto, LiveView

### Error Tracking
- ❌ **Sentry**: Optional, not configured (no DSN set)
- ✅ **Application Logs**: Standard logging via Logger
- ✅ **Prometheus Metrics**: Failure counters and rates

## Recommendations for Infrastructure Monitoring

Since we removed billing-specific infrastructure alerts, consider creating a **general infrastructure alerts file**:

**File**: `config/prometheus/infrastructure-alerts.yml`

```yaml
groups:
  - name: platform_infrastructure_alerts
    interval: 30s
    rules:
      # Database connection pool (affects all features)
      - alert: DatabaseConnectionPoolHigh
        expr: |
          (
            sum(db_connection_pool_size{app="rsolv"})
            -
            sum(db_connection_pool_available{app="rsolv"})
          ) / sum(db_connection_pool_size{app="rsolv"}) > 0.80
        for: 10m
        labels:
          severity: warning
          component: platform
          subsystem: database
        annotations:
          summary: "Database connection pool usage is high"
          description: "Platform-wide connection pool at {{ $value | humanizePercentage }}"

      # Application memory (affects all features)
      - alert: ApplicationMemoryHigh
        expr: |
          (
            container_memory_usage_bytes{namespace="rsolv-production", pod=~"rsolv-platform.*"}
            /
            container_spec_memory_limit_bytes{namespace="rsolv-production", pod=~"rsolv-platform.*"}
          ) > 0.80
        for: 15m
        labels:
          severity: warning
          component: platform
          subsystem: infrastructure
        annotations:
          summary: "Application memory usage is high"
          description: "Pod memory at {{ $value | humanizePercentage }}"
```

**Rationale**: Infrastructure issues affect the entire platform, so they should have **platform-wide ownership** rather than being owned by a specific feature team (billing, validation, etc.).

## Error Tracking Alternatives (Since No Sentry)

If you want error tracking without Sentry, consider:

1. **Structured Logging** (Already have):
   - Use `Logger` with structured metadata
   - Aggregate errors via Prometheus counter metrics
   - Query logs in Grafana Loki (if you have it)

2. **Prometheus Error Metrics** (Already implemented):
   - `rsolv_billing_payment_processed_total{status="failed"}`
   - `rsolv_billing_stripe_webhook_failed_total`
   - `rsolv_billing_invoice_failed_total`

3. **Free Sentry Plan**:
   - Sign up for free tier (5k events/month)
   - Set `SENTRY_DSN` environment variable
   - Configuration already exists and will activate

4. **Open Source Alternatives**:
   - **GlitchTip**: Sentry-compatible, self-hosted
   - **Bugsnag**: Alternative error tracking SaaS

## Summary

**Before**: 10 alerts + Sentry "configured"
**After**: 7 alerts + Sentry marked as optional

**Eliminated**:
- 3 infrastructure alerts (should be platform-wide, not billing-specific)
- Sentry verification steps (not actually configured)

**Preserved**:
- 7 truly billing-domain alerts
- All metrics collection (BillingPlugin, webhook telemetry)
- Grafana dashboard (10 panels)
- Operational runbooks (payment failures, webhook failures)

**Result**: **Leaner, more focused monitoring** with clear ownership boundaries.

---

**Updated Files**:
- `config/prometheus/billing-alerts.yml` - Removed 3 infrastructure alerts
- `projects/go-to-market-2025-10/BILLING-MONITORING-CONSOLIDATION.md` - This document
