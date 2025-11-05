# Week 5 Quick Reference Guide

**Status**: Active
**Timeline**: Nov 11-17, 2025
**Goal**: Production Launch Preparation

## Daily Checklist

### Monday: Staging Stability ✓
- [ ] Deploy latest to staging
- [ ] Configure monitoring
- [ ] Start 24h stability watch
- [ ] Document baseline metrics

### Tuesday: E2E Tests ✓
- [ ] Enhance E2E test suite
- [ ] Add CI/CD integration
- [ ] Document test procedures
- [ ] Verify 100% passing

### Wednesday: Load Testing ✓
- [ ] Run staging load tests
- [ ] Verify performance targets
- [ ] Document results
- [ ] Identify optimizations

### Thursday: Deployment ✓
- [ ] Finalize runbook
- [ ] Test rollback procedures
- [ ] Validate K8s secrets
- [ ] Document procedures

### Friday: Support & Monitoring ✓
- [ ] Complete customer docs
- [ ] Finalize dashboards
- [ ] Configure alerts
- [ ] Test alert delivery

## Critical Launch Gates

Must pass ALL to launch:

- [ ] E2E tests: 100% passing
- [ ] Load tests: < 5s P95 (target)
- [ ] Staging stable: 24+ hours
- [ ] Deployment tested
- [ ] Rollback verified
- [ ] Docs complete
- [ ] Monitoring operational
- [ ] Alerts configured

## Performance Targets

| Metric | Target | Current (ADR-032) |
|--------|--------|-------------------|
| Customer onboarding P95 | < 5s | 12.25ms ✅ |
| API response P95 | < 200ms | 12.44ms ✅ |
| Webhook processing P95 | < 1s | 12.44ms ✅ |
| Rate limit accuracy | 500/hour | Exact ✅ |

## Load Test Commands

```bash
# Run all tests
./scripts/load-tests/run-all-load-tests.sh staging

# Individual tests
k6 run scripts/load-tests/onboarding-load-test.k6.js
k6 run scripts/load-tests/credential-vending-load-test.k6.js
k6 run scripts/load-tests/webhook-load-test.k6.js
```

## E2E Test Commands

```bash
# Full E2E suite
mix test test/e2e/

# Production E2E
./test/e2e/production_e2e_test.sh

# Webhook tests
./test/e2e/webhook_production_test.sh
```

## Staging Verification

```bash
# Health check
curl -s https://api.rsolv-staging.com/health | jq .

# Pod status
kubectl get pods -n rsolv-staging

# Database check
mix run -e "Rsolv.Repo.query!(\"SELECT 1\")"
```

## Rollback Procedures

### Feature Flag (Instant)
```elixir
FunWithFlags.disable(:automated_customer_onboarding)
```

### Database Migration
```bash
mix ecto.rollback --step 1
```

### Application Version
```bash
kubectl rollout undo deployment/rsolv-app -n rsolv-staging
```

## Documentation To Complete

### Customer-Facing
- [ ] Getting Started Guide
- [ ] Billing FAQ
- [ ] Troubleshooting Guide

### Internal
- [ ] Deployment Runbook
- [ ] Rollback Procedures
- [ ] Monitoring Guide
- [ ] Support Escalation

## Current Status (2025-11-05)

### ✅ Completed (RFC-069)
- Billing integration (ADR-032)
- E2E customer journey tests (11 tests)
- Load test infrastructure (k6 scripts)
- Security validation (rate limiting, webhooks)
- Platform tests (4786/4786 passing)

### 🔄 In Progress
- GitHub Marketplace approval
- OpenAPI specs (65% complete)

### ⏳ This Week
- Final staging verification
- Production E2E tests
- Load test execution
- Deployment runbook
- Support documentation
- Monitoring finalization

## Key Resources

**Full Plan**: `RFCs/RFC-064-WEEK-5-PRODUCTION-PREPARATION-PLAN.md`
**Integration Status**: `ADRs/ADR-032-BILLING-INTEGRATION-COMPLETION.md`
**Master Plan**: `RFCs/RFC-064-BILLING-PROVISIONING-MASTER-PLAN.md`

## Go/No-Go Decision (Friday EOD)

Review all launch gates:
- All critical tasks complete?
- All tests passing?
- Staging stable 24+ hours?
- Documentation complete?
- Monitoring operational?
- Team ready?

**If YES**: Proceed to Week 6 launch
**If NO**: Identify blockers, extend Week 5
