# Staging Environment Deployment Guide

**RFC-068 Week 3 Implementation**
**Last Updated:** 2025-10-26
**Status:** Complete

> **📖 Infrastructure Setup**: For Kubernetes cluster setup and general infrastructure deployment, see [RSOLV-infrastructure/DEPLOYMENT.md](../../RSOLV-infrastructure/DEPLOYMENT.md). This guide focuses on billing-specific staging procedures.

## Overview

This guide covers deploying and managing the RSOLV staging environment with billing system integration, test data fixtures, and telemetry validation.

## Prerequisites

- kubectl access to staging cluster
- Stripe test mode API keys
- PostgreSQL staging database
- Prometheus + Grafana for metrics
- Tailscale access (optional, for remote access)

## Quick Start

```bash
# 1. Verify kubectl access
kubectl config use-context staging
kubectl get pods

# 2. Deploy latest staging image
kubectl set image deployment/rsolv rsolv=rsolv:staging-latest

# 3. Run migrations
kubectl exec -it deployment/rsolv -- bin/rsolv eval "Rsolv.ReleaseTasks.migrate()"

# 4. Reset test data
kubectl exec -it deployment/rsolv -- bin/rsolv eval "Rsolv.ReleaseTasks.reset_staging_data()"

# 5. Verify deployment
kubectl exec -it deployment/rsolv -- bin/rsolv eval "Rsolv.ReleaseTasks.health_check()"
```

## Environment Configuration

### Required Environment Variables

Create `staging.env` (never commit to git):

```bash
# Database
DATABASE_URL=postgresql://user:pass@staging-db:5432/rsolv_staging
DATABASE_SSL=true

# Application
SECRET_KEY_BASE=<generate with: mix phx.gen.secret>
PHX_HOST=staging.rsolv.dev
PORT=4000
MIX_ENV=staging
RELEASE_ENV=staging

# Stripe (TEST MODE ONLY)
STRIPE_API_KEY=sk_test_7upzEpVpOJlEJr4HwfSHObSe
STRIPE_PUBLISHABLE_KEY=pk_test_Prw2ZQauqnSEnJNq7BR7ZsbychP2t
STRIPE_WEBHOOK_SECRET=whsec_test_<get from Stripe dashboard>

# Monitoring
PROMETHEUS_PUSHGATEWAY_URL=http://prometheus-pushgateway:9091
GRAFANA_URL=http://grafana:3000

# Feature Flags
ENABLE_BILLING_FEATURES=true
BILLING_TEST_MODE=true
```

### Kubernetes ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: rsolv-staging-config
  namespace: staging
data:
  PHX_HOST: "staging.rsolv.dev"
  PORT: "4000"
  MIX_ENV: "staging"
  ENABLE_BILLING_FEATURES: "true"
  BILLING_TEST_MODE: "true"
```

### Kubernetes Secrets

```bash
# Create secrets from staging.env
kubectl create secret generic rsolv-staging-secrets \
  --from-env-file=staging.env \
  --namespace=staging
```

## Deployment Process

### 1. Build and Push Staging Image

```bash
# Build Docker image
docker build -t rsolv:staging-$(git rev-parse --short HEAD) .
docker tag rsolv:staging-$(git rev-parse --short HEAD) rsolv:staging-latest

# Push to registry
docker push rsolv:staging-$(git rev-parse --short HEAD)
docker push rsolv:staging-latest
```

### 2. Deploy to Kubernetes

```bash
# Apply configurations
kubectl apply -f k8s/staging/

# Update deployment
kubectl set image deployment/rsolv \
  rsolv=rsolv:staging-$(git rev-parse --short HEAD) \
  --namespace=staging

# Wait for rollout
kubectl rollout status deployment/rsolv --namespace=staging
```

### 3. Run Database Migrations

```bash
# Run migrations
kubectl exec -it deployment/rsolv --namespace=staging -- \
  bin/rsolv eval "Rsolv.ReleaseTasks.migrate()"

# Verify migration status
kubectl exec -it deployment/rsolv --namespace=staging -- \
  bin/rsolv eval "Rsolv.ReleaseTasks.health_check()"
```

### 4. Configure Stripe Webhooks

1. Go to [Stripe Dashboard (Test Mode)](https://dashboard.stripe.com/test/webhooks)
2. Create endpoint: `https://staging.rsolv.dev/webhooks/stripe`
3. Select events:
   - `customer.subscription.created`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
   - `invoice.payment_succeeded`
   - `invoice.payment_failed`
4. Copy webhook signing secret
5. Update secret:

```bash
kubectl create secret generic stripe-webhook-secret \
  --from-literal=secret=whsec_test_... \
  --namespace=staging \
  --dry-run=client -o yaml | kubectl apply -f -
```

## Test Data Management

### Test Customer Fixtures

The staging environment includes pre-seeded test customers in various billing states:

| Email | State | Credits | Description |
|-------|-------|---------|-------------|
| `trial-new@test.example.com` | Trial (new) | 5 | Just signed up, no billing |
| `trial-billing@test.example.com` | Trial + billing | 10 | Added payment method |
| `trial-expired@test.example.com` | Trial expired | 0 | Exhausted credits |
| `payg@test.example.com` | PAYG active | 0 | Pay per fix |
| `pro@test.example.com` | Pro active | 60 | Active subscription |
| `pro-partial@test.example.com` | Pro active | 45 | 15 fixes used |
| `pro-pastdue@test.example.com` | Pro past due | 60 | Payment failed |
| `pro-cancelled@test.example.com` | Pro cancelled | 5 | Preserved credits |
| `pro-scheduled@test.example.com` | Pro (cancel scheduled) | 60 | Active until period end |
| `pro-rollover@test.example.com` | Pro + rollover | 70 | 10 rollover credits |

### Reset Test Data

To reset staging with fresh test fixtures:

```bash
# Via kubectl exec
kubectl exec -it deployment/rsolv --namespace=staging -- \
  bin/rsolv eval "Rsolv.ReleaseTasks.reset_staging_data()"

# Via remote console
kubectl exec -it deployment/rsolv --namespace=staging -- \
  bin/rsolv remote
> Rsolv.ReleaseTasks.reset_staging_data()
```

**Safety:** `reset_staging_data/0` will REFUSE to run in `:prod` environment.

### Manual Test Data Creation

```elixir
# Connect to remote console
kubectl exec -it deployment/rsolv --namespace=staging -- bin/rsolv remote

# Create custom test customer
alias Rsolv.CustomerFactory

customer = CustomerFactory.insert(:customer)
  |> CustomerFactory.with_pro_plan()
  |> CustomerFactory.with_rollover_credits(10)
```

## Monitoring and Telemetry

### Accessing Grafana Dashboards

1. **Via Tailscale** (if configured):
   ```bash
   open http://staging-grafana.tailnet.ts.net:3000
   ```

2. **Via kubectl port-forward**:
   ```bash
   kubectl port-forward svc/grafana 3000:3000 --namespace=staging
   open http://localhost:3000
   ```

### Import Billing Dashboard

```bash
# Upload dashboard to Grafana
curl -X POST http://staging-grafana:3000/api/dashboards/db \
  -H "Authorization: Bearer ${GRAFANA_TOKEN}" \
  -H "Content-Type: application/json" \
  -d @config/monitoring/billing_dashboard.json
```

### Validate Dashboard

```bash
# Run validation script
GRAFANA_URL=http://staging-grafana:3000 \
GRAFANA_TOKEN=your_token \
mix run scripts/validate_billing_dashboard.exs --grafana
```

### Key Metrics to Monitor

- **Subscription Creation Rate**: `rsolv_billing_subscription_created_total`
- **Payment Success Rate**: `rsolv_billing_payment_processed_total{status="success"}`
- **Revenue**: `rsolv_billing_invoice_paid_amount_cents`
- **Usage**: `rsolv_billing_usage_tracked_total`
- **Cancellation Rate**: `rsolv_billing_subscription_cancelled_total`

## Testing Billing Workflows

### 1. Signup Flow

```bash
# Create new customer
curl -X POST https://staging.rsolv.dev/api/v1/customers \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newuser@test.example.com",
    "name": "Test User"
  }'

# Verify in Grafana: Check "Signups" panel
```

### 2. Add Billing

```bash
# Add payment method (using Stripe test card)
curl -X POST https://staging.rsolv.dev/api/v1/customers/{id}/billing \
  -H "Content-Type: application/json" \
  -d '{
    "payment_method": "pm_card_visa"
  }'

# Verify: Credits should increase from 5 to 10
```

### 3. Subscribe to Pro

```bash
# Create Pro subscription
curl -X POST https://staging.rsolv.dev/api/v1/subscriptions \
  -H "Content-Type: application/json" \
  -d '{
    "customer_id": "{id}",
    "plan": "pro"
  }'

# Verify in Grafana: "Pro Subscriptions" should increment
```

### 4. Simulate Webhook Events

```bash
# Simulate successful invoice payment
mix run scripts/webhooks/simulate_invoice_paid.exs

# Simulate failed payment
mix run scripts/webhooks/simulate_invoice_failed.exs

# Simulate subscription cancellation
mix run scripts/webhooks/simulate_subscription_deleted.exs
```

## Troubleshooting

### Database Connection Issues

```bash
# Test database connectivity
kubectl exec -it deployment/rsolv --namespace=staging -- \
  bin/rsolv eval "Rsolv.Repo.query!(\"SELECT 1\")"

# Check DATABASE_URL secret
kubectl get secret rsolv-staging-secrets --namespace=staging -o jsonpath='{.data.DATABASE_URL}' | base64 -d
```

### Stripe Webhook Failures

```bash
# Check webhook endpoint health
curl https://staging.rsolv.dev/webhooks/stripe/health

# View webhook logs
kubectl logs -f deployment/rsolv --namespace=staging | grep webhook

# Verify webhook secret
kubectl get secret stripe-webhook-secret --namespace=staging -o jsonpath='{.data.secret}' | base64 -d
```

### Missing Test Data

```bash
# Reset test data
kubectl exec -it deployment/rsolv --namespace=staging -- \
  bin/rsolv eval "Rsolv.ReleaseTasks.reset_staging_data()"

# Verify customer count
kubectl exec -it deployment/rsolv --namespace=staging -- \
  bin/rsolv eval "Rsolv.Repo.aggregate(Rsolv.Customers.Customer, :count)"
```

### Metrics Not Appearing

```bash
# Check PromEx plugin is loaded
kubectl exec -it deployment/rsolv --namespace=staging -- \
  bin/rsolv eval "Application.get_env(:rsolv, :prom_ex)"

# Emit test events
mix run scripts/validate_billing_dashboard.exs

# Query Prometheus directly
curl "http://staging-prometheus:9090/api/v1/query?query=rsolv_billing_subscription_created_total"
```

## Rollback Procedure

```bash
# List recent deployments
kubectl rollout history deployment/rsolv --namespace=staging

# Rollback to previous version
kubectl rollout undo deployment/rsolv --namespace=staging

# Rollback to specific revision
kubectl rollout undo deployment/rsolv --revision=3 --namespace=staging

# Rollback database migrations (if needed)
kubectl exec -it deployment/rsolv --namespace=staging -- \
  bin/rsolv eval "Rsolv.ReleaseTasks.rollback(Rsolv.Repo, 20241026000000)"
```

## Validation Checklist

Before considering staging deployment complete:

- [ ] Application pods running and healthy
- [ ] Database migrations applied successfully
- [ ] Test customer fixtures created (10 customers)
- [ ] Stripe webhook endpoint responding
- [ ] Webhook events processed successfully
- [ ] Grafana billing dashboard displays metrics
- [ ] Test telemetry events appear in dashboard < 30s
- [ ] All 10 test customer states accessible
- [ ] Payment processing works with test cards
- [ ] Subscription lifecycle tested (create → renew → cancel)

## Security Notes

**⚠️ CRITICAL:**
- Staging uses Stripe **TEST MODE** only
- All test customer emails use `@test.example.com` or `@example.com`
- Never use production credentials in staging
- Stripe webhook secret is environment-specific
- DATABASE_URL must point to staging database
- Rotate secrets if accidentally exposed

## Support and Resources

- **RFC-068**: See `RFCs/RFC-068-BILLING-TESTING-INFRASTRUCTURE.md`
- **Kubernetes Configs**: See `rsolv-infrastructure/k8s/staging/`
- **Deployment Docs**: See `rsolv-infrastructure/DEPLOYMENT.md`
- **Stripe Test Mode**: https://stripe.com/docs/testing
- **Test Cards**: https://stripe.com/docs/testing#cards

## Next Steps

After staging deployment is verified:

1. Run E2E test suite against staging
2. Validate integration with GitHub Actions (RFC-060)
3. Test marketplace workflows (RFC-067)
4. Verify billing calculations (RFC-066)
5. Load test staging environment
6. Document any staging-specific behaviors
7. Plan production rollout (RFC-069)
