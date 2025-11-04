# Runbook: Billing Payment Failures

**Alert**: `BillingPaymentFailureRateHigh` / `BillingPaymentFailureRateCritical`
**Severity**: Warning / Critical
**Component**: billing/payment

## Alert Description

Payment processing failure rate has exceeded acceptable thresholds:
- **Warning**: >10% of payments failing for 15 minutes
- **Critical**: >25% of payments failing for 10 minutes

## Impact

- **Warning**: Some customers unable to complete payments, revenue impact
- **Critical**: Most customers cannot pay, significant revenue loss

## Immediate Actions

### Step 1: Assess Scope (2 minutes)

```bash
# Check current failure rate
curl http://prometheus:9090/api/v1/query?query='sum(rate(rsolv_billing_payment_processed_total{status="failed"}[5m]))/sum(rate(rsolv_billing_payment_processed_total[5m]))'

# Check failure breakdown by payment method
curl http://prometheus:9090/api/v1/query?query='sum by (payment_method) (rate(rsolv_billing_payment_processed_total{status="failed"}[5m]))'

# Check Grafana dashboard
# https://grafana.rsolv.dev/d/billing-metrics
```

### Step 2: Check Stripe Status (1 minute)

```bash
# Visit Stripe status page
open https://status.stripe.com

# Check for ongoing incidents
# If Stripe is experiencing issues, wait for resolution
# Monitor Stripe status page and Slack notifications
```

### Step 3: Verify API Key Validity (2 minutes)

```bash
# Connect to production pod
kubectl exec -it -n rsolv-production deployment/rsolv-platform -- /app/bin/rsolv remote

# In IEx console, test Stripe API key
Stripe.Customer.list(%{limit: 1})

# Expected: {:ok, %Stripe.List{data: [...]}}
# If error: API key is invalid or Stripe is down
```

### Step 4: Check Recent Deployments (1 minute)

```bash
# Check recent deployments
kubectl rollout history deployment/rsolv-platform -n rsolv-production

# Check deployment age
kubectl get deployment/rsolv-platform -n rsolv-production -o jsonpath='{.metadata.creationTimestamp}'

# If deployment is <1 hour old, consider rollback
```

## Detailed Investigation

### Check Application Logs

```bash
# Check for payment-related errors
kubectl logs -n rsolv-production deployment/rsolv-platform --tail=100 \
  | grep -i "payment\|stripe\|invoice"

# Common errors:
# - "invalid_request_error" - API key or request format issue
# - "card_error" - Customer payment method issue (expected, not systemic)
# - "rate_limit_error" - Hitting Stripe API rate limits
# - "api_connection_error" - Network issue to Stripe
```

### Check Stripe Dashboard

1. Login to Stripe Dashboard: https://dashboard.stripe.com
2. Navigate to Payments
3. Filter by Failed payments in last 1 hour
4. Look for patterns:
   - **Single customer**: Customer-specific issue (expired card, insufficient funds)
   - **Multiple customers**: Systemic issue
   - **Specific card type**: Card network issue (Visa, Mastercard)
   - **Specific decline code**: See Stripe decline codes below

### Check Database Connectivity

```bash
# Check database connection pool
kubectl exec -n rsolv-production deployment/rsolv-platform -- \
  /app/bin/rsolv eval 'Ecto.Adapters.SQL.query!(Rsolv.Repo, "SELECT 1")'

# Check connection pool metrics
curl http://prometheus:9090/api/v1/query?query='db_connection_pool_available{namespace="rsolv-production"}'
```

### Check Webhook Processing

```bash
# Verify webhooks are being processed
kubectl logs -n rsolv-production deployment/rsolv-platform \
  | grep "Stripe webhook received"

# Check Oban job queue backlog
kubectl exec -n rsolv-production deployment/rsolv-platform -- \
  /app/bin/rsolv eval 'Oban.check_queue(:default) |> IO.inspect()'
```

## Common Causes & Solutions

### Cause 1: Stripe API Key Invalid/Revoked

**Symptoms**:
- All payments failing
- Error: "invalid_request_error: Invalid API Key"

**Solution**:
```bash
# Rotate API key in Stripe Dashboard
# Update production secret
kubectl create secret generic rsolv-stripe \
  --from-literal=STRIPE_API_KEY="sk_live_new_key" \
  --from-literal=STRIPE_WEBHOOK_SECRET="whsec_existing" \
  -n rsolv-production \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart deployment to pick up new secret
kubectl rollout restart deployment/rsolv-platform -n rsolv-production
```

### Cause 2: Stripe API Rate Limiting

**Symptoms**:
- Intermittent failures
- Error: "rate_limit_error"
- High request volume

**Solution**:
```bash
# Check current request rate
curl http://prometheus:9090/api/v1/query?query='rate(http_requests_total{path=~".*stripe.*"}[5m])'

# Reduce request rate:
# 1. Check for retry loops in code
# 2. Implement exponential backoff
# 3. Contact Stripe to increase rate limits

# Temporary: Disable non-essential Stripe API calls
kubectl set env deployment/rsolv-platform \
  ENABLE_STRIPE_SYNC=false \
  -n rsolv-production
```

### Cause 3: Payment Method Issues (Expected)

**Symptoms**:
- Specific customers failing
- Error codes: card_declined, insufficient_funds, expired_card
- Pattern: Random distribution across customers

**Solution**:
This is **expected behavior** - customers need to update payment methods.

```bash
# Check failure distribution
kubectl logs -n rsolv-production deployment/rsolv-platform \
  | grep "payment.*failed" \
  | awk '{print $NF}' \
  | sort | uniq -c

# If failures are distributed across many customers:
# - Send email notifications to affected customers
# - Update customer-facing billing page to show status
# - No system-level action required
```

### Cause 4: Network Connectivity to Stripe

**Symptoms**:
- All payments failing
- Error: "api_connection_error"
- Timeout errors

**Solution**:
```bash
# Test connectivity from pod
kubectl exec -n rsolv-production deployment/rsolv-platform -- \
  curl -v https://api.stripe.com/v1/charges -u sk_test_key:

# Check egress network policies
kubectl get networkpolicies -n rsolv-production

# Check DNS resolution
kubectl exec -n rsolv-production deployment/rsolv-platform -- \
  nslookup api.stripe.com

# If network issue, contact infrastructure team
```

### Cause 5: Code Bug in Payment Processing

**Symptoms**:
- Started after recent deployment
- Specific error pattern in logs
- Failing consistently

**Solution**:
```bash
# Rollback to previous version
kubectl rollout undo deployment/rsolv-platform -n rsolv-production

# Verify rollback success
kubectl rollout status deployment/rsolv-platform -n rsolv-production

# Check failure rate after rollback
# Wait 10-15 minutes for metrics to update
```

## Stripe Decline Codes Reference

| Decline Code | Meaning | Customer Action Required |
|--------------|---------|--------------------------|
| `card_declined` | Generic decline | Contact card issuer |
| `insufficient_funds` | Not enough money | Add funds or use different card |
| `expired_card` | Card expired | Update card expiration date |
| `incorrect_cvc` | Wrong CVV | Re-enter CVV |
| `processing_error` | Temporary issue | Retry payment |
| `card_velocity_exceeded` | Too many charges | Wait 24h or use different card |
| `do_not_honor` | Bank declined | Contact bank |
| `fraudulent` | Suspected fraud | Contact bank |

## Escalation

### Escalate If:
- Failure rate >25% for >30 minutes
- Stripe status page shows no issues
- Rollback doesn't resolve issue
- Cannot determine root cause within 15 minutes

### Escalation Path:
1. **Primary On-Call**: admin@rsolv.dev (PagerDuty)
2. **Engineering Lead**: dylan@rsolv.dev
3. **Stripe Support**: https://support.stripe.com (for API issues)

## Post-Incident

### 1. Document Incident

Create incident report in `/docs/incidents/YYYY-MM-DD-billing-payment-failures.md`:

```markdown
# Billing Payment Failure Incident

**Date**: YYYY-MM-DD HH:MM UTC
**Duration**: X minutes
**Impact**: Y% of payments failed
**Root Cause**: <description>
**Resolution**: <actions taken>
**Follow-up**: <prevent recurrence>
```

### 2. Review Metrics

```bash
# Check total failed payments during incident
curl http://prometheus:9090/api/v1/query?query='sum(increase(rsolv_billing_payment_processed_total{status="failed"}[1h]))'

# Estimate revenue impact
# Failed payments * average payment amount ($49/mo Pro plan)
```

### 3. Customer Communication

If impact >10% for >1 hour:
- Send status update to affected customers
- Update billing status page
- Document in changelog

### 4. Prevent Recurrence

- Update alert thresholds if needed
- Add monitoring for new failure modes
- Implement additional retry logic
- Add circuit breaker for Stripe API
- Document new failure patterns

## Testing

To test this runbook:

```bash
# 1. Use Stripe test mode with declined test cards
# Test card: 4000 0000 0000 0002 (generic_decline)

# 2. Verify alert fires
# Check Prometheus alerts page

# 3. Follow runbook steps
# Document time taken for each step

# 4. Verify resolution
# Check failure rate returns to <5%
```

## Maintenance

**Review**: Quarterly
**Last Updated**: 2025-11-04
**Owner**: Billing Team
