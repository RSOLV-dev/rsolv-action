# k6 Load Testing Suite - RFC-068

Performance and load testing for RSOLV billing and credential vending APIs.

## Quick Start

```bash
# Run all three load tests against staging
./scripts/load-tests/run-all-load-tests.sh staging

# Run individual tests
k6 run scripts/load-tests/onboarding-load-test.k6.js
k6 run scripts/load-tests/credential-vending-load-test.k6.js
k6 run scripts/load-tests/webhook-load-test.k6.js
```

## Test Suite Overview

| Test | Target RPS | Duration | Purpose |
|------|-----------|----------|---------|
| Customer Onboarding | 100 | 5 min sustained | Test signup API under load |
| Credential Vending | 200 | 5 min sustained | Test AI credential exchange |
| Webhook Processing | 50 | 5 min sustained | Test Stripe webhook handling |

## Prerequisites

### Install k6

```bash
# macOS
brew install k6

# Linux
curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash

# Verify installation
k6 version
```

### Environment Setup

Create test API keys in staging before running credential vending tests:

```bash
# In Rails console or via API
export TEST_API_KEY_1="rsolv_staging_test_key_1"
export TEST_API_KEY_2="rsolv_staging_test_key_2"
export TEST_API_KEY_3="rsolv_staging_test_key_3"
export TEST_API_KEY_4="rsolv_staging_test_key_4"
export TEST_API_KEY_5="rsolv_staging_test_key_5"

# Optional: Webhook secret for signature validation
export STRIPE_WEBHOOK_SECRET="whsec_test_secret"

# Set API URL (default: staging)
export API_URL="https://api.rsolv-staging.com"
```

## Test Details

### 1. Customer Onboarding Load Test

**File**: `onboarding-load-test.k6.js`

**Endpoints**: `POST /api/v1/customers/onboard`

**Load Profile**:
- Ramp up: 1m to 20 RPS → 1m to 50 RPS → 1m to 100 RPS
- Sustain: 5 minutes at 100 RPS
- Ramp down: 1m to 0 RPS

**Validates**:
- Customer creation success rate
- API key generation
- Trial credit allocation (5 fixes)
- Rate limiting (10 req/min per IP)
- Response times (p95 < 2s)

**Expected Results**:
- Success rate: >90%
- P95 latency: <2000ms
- Rate limit triggers after 10 requests from same IP

### 2. Credential Vending Load Test

**File**: `credential-vending-load-test.k6.js`

**Endpoints**: `POST /api/v1/credentials/exchange`

**Load Profile**:
- Ramp up: 1m to 40 RPS → 1m to 100 RPS → 1m to 200 RPS
- Sustain: 5 minutes at 200 RPS
- Ramp down: 1m to 0 RPS

**Validates**:
- Credential generation for multiple providers
- TTL variations (1-4 hours)
- Per-customer rate limiting
- GitHub metadata tracking
- Response times (p95 < 1.5s)

**Expected Results**:
- Success rate: >85%
- P95 latency: <1500ms
- Rate limiting per customer enforced
- Multiple providers supported (Anthropic, OpenAI)

### 3. Webhook Processing Load Test

**File**: `webhook-load-test.k6.js`

**Endpoints**: `POST /api/webhooks/stripe`

**Load Profile**:
- Ramp up: 1m to 10 RPS → 1m to 25 RPS → 1m to 50 RPS
- Sustain: 5 minutes at 50 RPS
- Ramp down: 1m to 0 RPS

**Validates**:
- Multiple webhook event types
- Signature validation
- Idempotency (10% duplicate events)
- Event processing reliability
- Response times (p95 < 1s)

**Expected Results**:
- Success rate: >95%
- P95 latency: <1000ms
- Duplicate events handled gracefully
- All event types processed correctly

## Results and Metrics

### Output Files

All results are saved to `load_tests/results/`:

```
load_tests/results/
├── onboarding-2025-10-30_14-30-00.txt
├── onboarding-results.json
├── credential-vending-2025-10-30_14-45-00.txt
├── credential-vending-results.json
├── webhook-2025-10-30_15-00-00.txt
└── webhook-results.json
```

### Key Metrics

Each test reports:

- **Throughput**: Requests per second (RPS)
- **Latency**: avg, p50, p95, p99 response times
- **Success Rate**: % of successful requests
- **Error Rate**: % of failed requests
- **Rate Limiting**: Count of rate-limited requests
- **Custom Metrics**: Test-specific counters and trends

### Grafana Dashboards

Monitor real-time metrics during load tests:

```bash
# Port forward to Grafana (if using Kubernetes)
kubectl port-forward -n monitoring svc/grafana 3000:3000

# Open browser
open http://localhost:3000/d/billing-dashboard
```

Key panels to watch:
- Request rate by endpoint
- P95/P99 latency trends
- Error rate spikes
- Rate limit engagement
- Database connection pool usage
- Memory and CPU utilization

## Rate Limiting Verification

### Expected Rate Limits

| Endpoint | Limit | Window | Scope |
|----------|-------|--------|-------|
| Customer Onboarding | 10 req | 1 minute | Per IP |
| Credential Exchange | 60 req | 1 minute | Per Customer |
| Webhook Processing | 1000 req | 1 minute | Global |

### Testing Rate Limits

The load tests are designed to trigger rate limits:

1. **Onboarding**: Sends >10 requests from same IP to trigger 429 responses
2. **Credential Vending**: Uses 5 test API keys to distribute load and test per-customer limits
3. **Webhooks**: Ramps to 50 RPS to stay well below 1000/min global limit

Check `rate_limit_hits` metric in results to verify limits are working.

## Troubleshooting

### High Error Rates

If error rate exceeds thresholds:

1. Check staging environment health
2. Verify database connections available
3. Review application logs for errors
4. Check if rate limits are too aggressive
5. Verify test credentials are valid

### API Authentication Failures

```bash
# Verify test API keys exist and are active
curl -H "X-API-Key: $TEST_API_KEY_1" \
     https://api.rsolv-staging.com/api/health

# Expected: 200 OK
```

### Webhook Signature Validation

If webhook tests fail with 401/403:

```bash
# Verify webhook secret is correct
echo $STRIPE_WEBHOOK_SECRET

# Check Stripe CLI is forwarding correctly
stripe listen --forward-to localhost:4000/api/webhooks/stripe
```

### k6 Installation Issues

```bash
# Verify k6 is installed and in PATH
which k6

# Check version (requires 0.40.0+)
k6 version

# Reinstall if needed
brew reinstall k6
```

## Baseline Metrics Documentation

After running load tests, document results in:

**File**: `projects/go-to-market-2025-10/WEEK-3-LOAD-TEST-RESULTS.md`

Include:
- Date and environment tested
- Test configuration (RPS, duration)
- Key metrics (throughput, latency, error rate)
- Rate limiting observations
- System resource utilization
- Recommendations for production

## Next Steps

1. **Run baseline tests**: Execute all three load tests against staging
2. **Document results**: Create WEEK-3-LOAD-TEST-RESULTS.md with findings
3. **Tune parameters**: Adjust rate limits or scaling based on results
4. **Production testing**: Run smaller-scale tests in production after launch
5. **Continuous monitoring**: Integrate load testing into CI/CD pipeline

## References

- [RFC-068: Billing Testing Infrastructure](../../RFCs/RFC-068-BILLING-TESTING-INFRASTRUCTURE.md)
- [k6 Documentation](https://k6.io/docs/)
- [k6 Metrics Reference](https://k6.io/docs/using-k6/metrics/)
- [k6 Thresholds](https://k6.io/docs/using-k6/thresholds/)
