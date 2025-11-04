# Runbook: Stripe Webhook Failures

**Alert**: `StripeWebhookFailureRateHigh`
**Severity**: Warning
**Component**: billing/webhook

## Alert Description

Stripe webhook failure rate has exceeded 10% for 15 minutes. This indicates issues with webhook signature verification or processing.

## Impact

- **Medium**: Billing events (invoice.paid, subscription.created, etc.) may not be processed
- Customer billing records may be out of sync
- Credit grants may be delayed
- Subscription status updates may be delayed

## Immediate Actions

### Step 1: Assess Scope (2 minutes)

```bash
# Check current webhook failure rate
curl http://prometheus:9090/api/v1/query?query='sum(rate(rsolv_billing_stripe_webhook_received_total{status="failed"}[5m]))/sum(rate(rsolv_billing_stripe_webhook_received_total[5m]))'

# Check failure reasons
curl http://prometheus:9090/api/v1/query?query='sum by (failure_reason) (rate(rsolv_billing_stripe_webhook_failed_total[5m]))'

# Check Grafana dashboard
# https://grafana.rsolv.dev/d/billing-metrics
```

### Step 2: Check Application Logs (2 minutes)

```bash
# Check for webhook errors
kubectl logs -n rsolv-production deployment/rsolv-platform --tail=100 \
  | grep "Stripe webhook"

# Common errors:
# - "Missing signature" - Signature header not present
# - "Invalid signature" - STRIPE_WEBHOOK_SECRET mismatch
# - "Signature expired" - Timestamp >5 minutes old
# - "Processing failed" - Error in webhook handler
```

### Step 3: Verify Webhook Endpoint (1 minute)

```bash
# Test webhook endpoint accessibility
curl -v https://api.rsolv.dev/api/webhooks/stripe

# Expected: 401 Unauthorized (missing signature)
# If timeout or 5xx: Endpoint not accessible
```

## Detailed Investigation

### Check Webhook Secret

```bash
# Get current webhook secret from Kubernetes
kubectl get secret rsolv-stripe -n rsolv-production -o jsonpath='{.data.STRIPE_WEBHOOK_SECRET}' | base64 -d

# Get webhook secret from Stripe Dashboard
# 1. Login to https://dashboard.stripe.com/webhooks
# 2. Click on production webhook endpoint
# 3. Click "Signing secret" → "Reveal"
# 4. Compare with Kubernetes secret

# If mismatch, update Kubernetes secret (see Solutions below)
```

### Check Webhook Configuration in Stripe

1. Login to Stripe Dashboard: https://dashboard.stripe.com/webhooks
2. Verify webhook endpoint URL: `https://api.rsolv.dev/api/webhooks/stripe`
3. Check "Events to send":
   - ✅ `invoice.paid`
   - ✅ `invoice.payment_failed`
   - ✅ `customer.subscription.created`
   - ✅ `customer.subscription.deleted`
   - ✅ `payment_method.attached`
4. Check "Status": Should be "Enabled"
5. Review "Recent deliveries" for failure patterns

### Check Oban Job Queue

```bash
# Check if webhooks are queued but not processing
kubectl exec -n rsolv-production deployment/rsolv-platform -- \
  /app/bin/rsolv eval 'Oban.check_queue(:default) |> IO.inspect()'

# Check Oban worker status
kubectl logs -n rsolv-production deployment/rsolv-platform \
  | grep "StripeWebhookWorker"

# If jobs are stuck, check for errors in worker processing
```

### Check Network/Firewall Rules

```bash
# Check if Stripe IPs are allowed
# Stripe webhook IPs: https://stripe.com/docs/ips

# Test from pod
kubectl exec -n rsolv-production deployment/rsolv-platform -- \
  curl -v https://hooks.stripe.com/adapter/v1/health

# Check ingress/network policies
kubectl get networkpolicies -n rsolv-production
kubectl get ingress -n rsolv-production
```

## Common Causes & Solutions

### Cause 1: Webhook Secret Mismatch

**Symptoms**:
- 100% of webhooks failing
- Error: "Invalid signature"

**Solution**:
```bash
# Get correct webhook secret from Stripe Dashboard
# https://dashboard.stripe.com/webhooks → Click endpoint → Signing secret

# Update Kubernetes secret
kubectl create secret generic rsolv-stripe \
  --from-literal=STRIPE_API_KEY="<existing_key>" \
  --from-literal=STRIPE_WEBHOOK_SECRET="whsec_<new_secret>" \
  -n rsolv-production \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart deployment
kubectl rollout restart deployment/rsolv-platform -n rsolv-production

# Verify after restart
kubectl logs -n rsolv-production deployment/rsolv-platform | grep "Stripe webhook received"
```

### Cause 2: Timestamp Skew (Signature Expired)

**Symptoms**:
- Intermittent failures
- Error: "Signature expired"
- Time difference >5 minutes

**Solution**:
```bash
# Check pod clock
kubectl exec -n rsolv-production deployment/rsolv-platform -- date -u

# Compare with actual UTC time
date -u

# If >5 minutes difference, check NTP sync on nodes
kubectl get nodes -o wide

# Restart pods to resync time
kubectl rollout restart deployment/rsolv-platform -n rsolv-production
```

### Cause 3: Webhook Processing Errors

**Symptoms**:
- Specific event types failing
- Error: "Processing failed"
- Worker errors in logs

**Solution**:
```bash
# Check which event types are failing
kubectl logs -n rsolv-production deployment/rsolv-platform \
  | grep "Stripe webhook.*failed" \
  | awk '{print $(NF-1)}' \
  | sort | uniq -c

# Review StripeWebhookWorker code for bugs
# lib/rsolv/workers/stripe_webhook_worker.ex

# Check Oban failed jobs
kubectl exec -n rsolv-production deployment/rsolv-platform -- \
  /app/bin/rsolv eval 'Oban.Job |> Rsolv.Repo.all() |> Enum.filter(&(&1.state == :discarded)) |> length()'

# If code bug, rollback deployment
kubectl rollout undo deployment/rsolv-platform -n rsolv-production
```

### Cause 4: Endpoint Not Accessible from Stripe

**Symptoms**:
- All webhooks failing
- Stripe dashboard shows "Endpoint not reachable"
- Timeout errors

**Solution**:
```bash
# Test endpoint from external network
curl -v https://api.rsolv.dev/api/webhooks/stripe \
  -H "stripe-signature: t=invalid,v1=invalid"

# Expected: 401 Unauthorized (invalid signature)
# If timeout: DNS, ingress, or firewall issue

# Check ingress configuration
kubectl get ingress -n rsolv-production -o yaml | grep -A 10 "webhooks"

# Check service
kubectl get service -n rsolv-production

# Check pod health
kubectl get pods -n rsolv-production
```

### Cause 5: High Webhook Processing Duration

**Symptoms**:
- Webhooks timing out (>30s)
- Alert: StripeWebhookProcessingDurationHigh
- Stripe retrying webhooks

**Solution**:
```bash
# Check webhook processing duration
curl http://prometheus:9090/api/v1/query?query='histogram_quantile(0.95, rate(rsolv_billing_stripe_webhook_received_duration_milliseconds_bucket[5m]))'

# If >30s, check for:
# 1. Slow database queries
kubectl exec -n rsolv-production deployment/rsolv-platform -- \
  /app/bin/rsolv eval 'Ecto.Adapters.SQL.query!(Rsolv.Repo, "SELECT * FROM pg_stat_activity WHERE state = '\''active'\'' AND query_start < NOW() - INTERVAL '\''30 seconds'\''")'

# 2. Slow Stripe API calls
kubectl logs -n rsolv-production deployment/rsolv-platform \
  | grep "Stripe API" \
  | grep -o "duration=[0-9]*" \
  | sort -n

# Solution: Optimize queries or increase resources
kubectl scale deployment/rsolv-platform --replicas=4 -n rsolv-production
```

## Stripe Webhook Retry Behavior

Stripe will retry failed webhooks:
- Initial retry: Immediately
- Subsequent retries: Every hour for 72 hours
- After 72 hours: Webhook is disabled

**Important**: Fix issues within 72 hours to avoid webhook deactivation.

## Escalation

### Escalate If:
- Failure rate >50% for >30 minutes
- Cannot determine root cause within 15 minutes
- Webhook secret is correct but still failing
- Stripe reports endpoint is unreachable

### Escalation Path:
1. **Primary On-Call**: admin@rsolv.dev
2. **Engineering Lead**: dylan@rsolv.dev
3. **Infrastructure Team**: For network/DNS issues
4. **Stripe Support**: https://support.stripe.com (for Stripe-side issues)

## Post-Incident

### 1. Reconcile Missed Events

```bash
# Get list of missed webhook events from Stripe
# Stripe Dashboard → Webhooks → [Your endpoint] → Recent deliveries
# Filter by "Failed" status during incident window

# Manually process missed events
kubectl exec -n rsolv-production deployment/rsolv-platform -- \
  /app/bin/rsolv eval '
    # Example: Reprocess invoice.paid event
    event_id = "evt_missing_123"
    Rsolv.Workers.StripeWebhookWorker.new(%{
      stripe_event_id: event_id,
      event_type: "invoice.paid",
      event_data: %{}
    }) |> Oban.insert()
  '
```

### 2. Verify Customer Data Integrity

```bash
# Check for customers with out-of-sync billing data
kubectl exec -n rsolv-production deployment/rsolv-platform -- \
  /app/bin/rsolv eval '
    # Find customers with recent activity but no credit transactions
    recent_time = DateTime.utc_now() |> DateTime.add(-3600, :second)
    customers = Rsolv.Billing.Customer
      |> where([c], c.inserted_at > ^recent_time)
      |> Rsolv.Repo.all()

    Enum.each(customers, fn customer ->
      # Verify credit balance matches Stripe
      IO.puts("Customer: #{customer.id}, Credits: #{customer.credit_balance}")
    end)
  '
```

### 3. Document Incident

Create incident report in `/docs/incidents/YYYY-MM-DD-webhook-failures.md`:

```markdown
# Stripe Webhook Failure Incident

**Date**: YYYY-MM-DD HH:MM UTC
**Duration**: X minutes
**Impact**: Y% of webhooks failed
**Root Cause**: <description>
**Resolution**: <actions taken>
**Missed Events**: <count>
**Data Reconciliation**: <status>
**Follow-up**: <prevent recurrence>
```

### 4. Prevent Recurrence

- Set up webhook secret rotation schedule (every 90 days)
- Add monitoring for webhook endpoint accessibility
- Implement webhook event logging to database
- Add webhook replay mechanism for failed events
- Document webhook debugging procedures

## Testing

To test this runbook:

```bash
# 1. Intentionally break webhook signature
kubectl set env deployment/rsolv-platform \
  STRIPE_WEBHOOK_SECRET="whsec_invalid_for_testing" \
  -n rsolv-staging

# 2. Trigger test webhook from Stripe CLI
stripe trigger invoice.paid --forward-to https://api.rsolv-staging.com/api/webhooks/stripe

# 3. Verify alert fires
# Check Prometheus alerts page

# 4. Follow runbook steps
# Document time taken for each step

# 5. Fix configuration
kubectl set env deployment/rsolv-platform \
  STRIPE_WEBHOOK_SECRET="<correct_secret>" \
  -n rsolv-staging

# 6. Verify webhooks succeed
stripe trigger invoice.paid --forward-to https://api.rsolv-staging.com/api/webhooks/stripe
```

## Reference: Webhook Event Types

| Event Type | Description | Handler |
|------------|-------------|---------|
| `invoice.paid` | Invoice successfully paid | Grant credits |
| `invoice.payment_failed` | Invoice payment failed | Email customer |
| `customer.subscription.created` | New subscription | Record subscription |
| `customer.subscription.deleted` | Subscription cancelled | Update status |
| `customer.subscription.updated` | Subscription changed | Update plan |
| `payment_method.attached` | Payment method added | Update billing |
| `charge.succeeded` | One-time charge succeeded | Record transaction |
| `charge.failed` | One-time charge failed | Email customer |

## Maintenance

**Review**: Quarterly
**Last Updated**: 2025-11-04
**Owner**: Billing Team
