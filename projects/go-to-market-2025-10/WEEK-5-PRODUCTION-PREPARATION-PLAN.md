# RFC-064 Week 5: Production Preparation Plan

**Status**: Active
**Created**: 2025-11-05
**Timeline**: Week 5 of RFC-064 (Nov 11-17, 2025)
**Prerequisites**: RFC-069 Integration Week completed
**Related**: RFC-064 (Master Plan), RFC-069 (Integration Week), ADR-032 (Billing Integration Completion)

## Executive Summary

Week 5 is the **final validation and preparation phase** before production launch in Week 6. All features are implemented and integrated (per ADR-032). This week focuses on **production readiness verification**, **deployment automation**, **support documentation**, and **launch preparation**.

**Critical Launch Gates** (Must Pass to Launch):
1. ✅ E2E test suite passing (signup → scan → billing → usage)
2. ⏳ Load tests pass (100 concurrent signups, < 5s P95)
3. ⏳ Staging stable for 24+ hours (no critical errors)
4. ⏳ Deployment runbooks tested
5. ⏳ Rollback procedures verified
6. ⏳ Support documentation complete
7. ⏳ Monitoring dashboards operational
8. ⏳ Alert thresholds configured and tested

## Current State Assessment (2025-11-05)

### ✅ Completed (RFC-069 Integration Week)

**Billing Integration (ADR-032):**
- Customer provisioning API operational
- Stripe billing integration working (test mode)
- Credit ledger tracking implemented
- Pro subscription lifecycle complete
- Webhook processing verified
- E2E customer journey tests passing (11 tests)

**Load Testing Infrastructure:**
- k6 load test suite created (3 test scripts)
- Staging environment deployed
- Performance baseline established (exceeded targets by 16-409x)
- Infrastructure capacity confirmed (88% CPU headroom)

**Security & Validation:**
- Rate limiting operational (10 signups/min/IP)
- Webhook signature verification (100% enforcement)
- Email validation (burnex integration)
- API key hashing (SHA256)

**Test Coverage:**
- Platform tests: 4786/4786 passing (100% green)
- E2E customer journey: 11 tests passing
- Billing integration tests operational
- Stripe webhook tests validated

### 🔄 In Progress

**GitHub Marketplace (RFC-067):**
- Submission prepared but not yet approved
- Not blocking production launch
- Multi-channel GTM strategy in place

**Documentation:**
- OpenAPI specs 65% complete (35% remaining)
- Support documentation partial
- Deployment runbooks in draft

### ⏳ To Complete This Week (Week 5)

**Critical for Launch:**
1. Final staging verification (24+ hours stable monitoring)
2. Production E2E test suite implementation
3. Load test execution on staging
4. Deployment runbook finalization
5. Rollback procedure testing
6. Support documentation completion
7. Monitoring dashboards finalization
8. Alert configuration and testing

**Nice to Have:**
- OpenAPI spec completion (can continue post-launch)
- Additional load test scenarios
- Performance optimization opportunities

## Week 5 Task Breakdown

### Monday (Day 1): Staging Stability Verification

**Objective**: Establish 24-hour stability baseline

**Tasks:**
- [ ] Deploy latest code to staging
- [ ] Verify all services healthy:
  - [ ] Phoenix application (2 pods)
  - [ ] PostgreSQL (CloudNativePG)
  - [ ] Redis (if used)
  - [ ] Feature flags (FunWithFlags)
- [ ] Configure comprehensive monitoring:
  - [ ] CPU/Memory metrics
  - [ ] Request rate and latency
  - [ ] Error rates
  - [ ] Database connection pool
  - [ ] Stripe webhook success rate
- [ ] Document baseline metrics
- [ ] Begin 24-hour observation period

**Deliverables:**
- Staging deployment verified
- Monitoring dashboards operational
- Baseline metrics documented
- 24-hour timer started

**Test Command:**
```bash
# Verify staging health
curl -s https://api.rsolv-staging.com/health | jq .

# Check K8s pod status
kubectl get pods -n rsolv-staging

# Verify database connectivity
mix run -e "Rsolv.Repo.query!(\"SELECT 1\")"

# Check Stripe webhook endpoint
curl -s https://api.rsolv-staging.com/webhooks/stripe | jq .
```

### Tuesday (Day 2): E2E Test Suite Enhancement

**Objective**: Complete production-ready E2E test coverage

**Current E2E Tests:**
- `test/e2e/customer_journey_test.exs` (11 tests)
- `test/e2e/webhook_integration_test.exs`
- `test/scripts/test_end_to_end.sh`

**Enhancement Tasks:**
- [ ] Add production E2E test script:
  - [ ] Signup flow (direct, marketplace, early access)
  - [ ] API key delivery verification
  - [ ] Credit balance tracking
  - [ ] Fix deployment billing
  - [ ] Pro subscription creation
  - [ ] Payment failure handling
- [ ] Create automated E2E runner:
  - [ ] Parallel execution support
  - [ ] Result aggregation
  - [ ] Failure reporting
- [ ] Document E2E test procedures
- [ ] Add E2E tests to CI/CD pipeline

**E2E Test Coverage Requirements:**
1. **Signup → First Fix** (Trial customer)
   - Signup with email
   - Receive API key
   - Deploy first fix
   - Verify credit consumption

2. **Trial → PAYG Conversion**
   - Add payment method
   - Receive bonus credits
   - Exhaust credits
   - Verify $29 charge

3. **Pro Subscription**
   - Subscribe to Pro plan
   - Receive 60 credits
   - Exhaust credits
   - Verify $15 overage charge
   - Subscription renewal

4. **Marketplace Flow**
   - Install from Marketplace
   - Complete signup
   - Receive API key
   - First scan execution

5. **Webhook Processing**
   - Payment success
   - Payment failure
   - Subscription created
   - Subscription cancelled
   - Invoice payment succeeded

**Deliverables:**
- Production E2E test suite complete
- E2E test documentation
- CI/CD integration configured
- E2E test results baseline

**Test Commands:**
```bash
# Run full E2E suite
mix test test/e2e/

# Run production E2E script
./test/e2e/production_e2e_test.sh

# Verify webhook processing
./test/e2e/webhook_production_test.sh
```

### Wednesday (Day 3): Load Testing & Performance Validation

**Objective**: Validate production capacity and performance

**Load Test Scenarios:**

1. **Customer Onboarding** (100 concurrent signups)
   - Target: < 5s P95 latency
   - Expected: ~12ms (per ADR-032)
   - Duration: 10 minutes sustained

2. **Credential Vending** (200 RPS)
   - Target: < 200ms P95
   - Expected: ~12ms
   - Duration: 10 minutes sustained

3. **Webhook Processing** (50 RPS)
   - Target: < 1s P95
   - Expected: ~12ms
   - Duration: 10 minutes sustained

**Tasks:**
- [ ] Execute staging load tests:
  ```bash
  ./scripts/load-tests/run-all-load-tests.sh staging
  ```
- [ ] Verify performance targets met:
  - [ ] Customer onboarding < 5s P95
  - [ ] API response time < 200ms P95
  - [ ] Webhook processing < 1s P95
  - [ ] Rate limiting accurate (500/hour)
  - [ ] No connection pool timeouts
  - [ ] Memory stable (< 80% utilization)
- [ ] Identify performance bottlenecks
- [ ] Optimize critical paths if needed
- [ ] Document load test results
- [ ] Create performance baseline report

**Monitoring During Load Tests:**
- CPU utilization (should stay < 50%)
- Memory usage (should stay < 80%)
- Database connection pool (no exhaustion)
- Response time percentiles (P50, P95, P99)
- Error rates (should be < 1%)
- Stripe API latency

**Deliverables:**
- Load test results report
- Performance baseline documented
- Bottlenecks identified and resolved
- Capacity plan for production

**Load Test Commands:**
```bash
# Run all load tests
./scripts/load-tests/run-all-load-tests.sh staging

# Individual tests
k6 run scripts/load-tests/onboarding-load-test.k6.js
k6 run scripts/load-tests/credential-vending-load-test.k6.js
k6 run scripts/load-tests/webhook-load-test.k6.js

# Monitor results
ls -lh load_tests/results/
```

### Thursday (Day 4): Deployment Runbooks & Rollback Testing

**Objective**: Production deployment procedures battle-tested

**Deployment Runbook Tasks:**
- [ ] Create production deployment checklist:
  - [ ] Pre-deployment verification
  - [ ] Secret validation (use pre-flight script)
  - [ ] Database migration verification
  - [ ] Feature flag configuration
  - [ ] Stripe key configuration (prod keys)
  - [ ] DNS/routing verification
  - [ ] Post-deployment smoke tests
- [ ] Document rollback procedures:
  - [ ] Feature flag disable
  - [ ] Database rollback (if needed)
  - [ ] Application rollback
  - [ ] Communication procedures
- [ ] Test rollback on staging:
  - [ ] Deploy feature-flagged code
  - [ ] Enable feature flag
  - [ ] Verify functionality
  - [ ] Disable feature flag
  - [ ] Verify graceful degradation
  - [ ] Re-enable and verify recovery

**Pre-flight Secret Validation:**
Per ADR-032, create script to validate K8s secrets:
```bash
#!/bin/bash
# scripts/validate_k8s_secrets.sh

# Validate DATABASE_URL format
# Validate SECRET_KEY_BASE length (64 hex)
# Validate Stripe keys format
# Validate required secrets present
```

**Rollback Scenarios to Test:**
1. **Feature Flag Rollback** (instant, no deployment)
   ```elixir
   # Disable automated onboarding
   FunWithFlags.disable(:automated_customer_onboarding)
   ```

2. **Database Migration Rollback**
   ```bash
   mix ecto.rollback --step 1
   ```

3. **Application Version Rollback**
   ```bash
   kubectl rollout undo deployment/rsolv-app -n rsolv-production
   ```

**Deliverables:**
- Deployment runbook complete
- Rollback procedures documented
- Rollback tested on staging
- Secret validation script operational
- Communication templates prepared

**Test Commands:**
```bash
# Test deployment
kubectl apply -f kubernetes/staging/

# Verify deployment
kubectl get pods -n rsolv-staging
kubectl logs -n rsolv-staging deployment/rsolv-app --tail=100

# Test rollback
kubectl rollout undo deployment/rsolv-app -n rsolv-staging
kubectl rollout status deployment/rsolv-app -n rsolv-staging
```

### Friday (Day 5): Support Documentation & Monitoring Finalization

**Objective**: Support team enabled, monitoring operational

**Support Documentation Tasks:**
- [ ] Create customer onboarding guide:
  - [ ] Signup process (direct, marketplace)
  - [ ] API key delivery and security
  - [ ] First fix deployment
  - [ ] Credit system explanation
  - [ ] Payment method addition
  - [ ] Pro subscription process
- [ ] Create billing FAQ:
  - [ ] Trial credits (5-10 free)
  - [ ] PAYG pricing ($29/fix)
  - [ ] Pro pricing ($599/month, 60 credits, $15 overage)
  - [ ] Credit tracking
  - [ ] Subscription management
  - [ ] Payment failure handling
- [ ] Create troubleshooting guide:
  - [ ] Common signup issues
  - [ ] API key not received
  - [ ] Payment method errors
  - [ ] Webhook failures
  - [ ] Credit balance discrepancies
- [ ] Document support escalation procedures

**Monitoring Dashboard Tasks:**
- [ ] Finalize Grafana dashboards:
  - [ ] **Billing Metrics**: Signups, conversions, revenue
  - [ ] **System Health**: CPU, memory, connections
  - [ ] **API Performance**: Latency, throughput, errors
  - [ ] **Stripe Integration**: Webhook success, payment success
  - [ ] **Customer Metrics**: Trial, PAYG, Pro counts
- [ ] Configure alerts:
  - [ ] Connection pool > 80%
  - [ ] Memory > 80%
  - [ ] Error rate > 5%
  - [ ] Stripe webhook failures
  - [ ] Payment failure rate > 10%
  - [ ] Customer signup drop-off
- [ ] Test alert delivery
- [ ] Document alert response procedures

**Alert Configuration:**
```yaml
# Example Prometheus alert rules
groups:
  - name: billing_alerts
    interval: 1m
    rules:
      - alert: HighPaymentFailureRate
        expr: rate(stripe_payment_failures[5m]) > 0.1
        for: 5m
        annotations:
          summary: "Payment failure rate above 10%"

      - alert: ConnectionPoolExhaustion
        expr: db_pool_usage > 0.8
        for: 2m
        annotations:
          summary: "Database connection pool > 80%"
```

**Deliverables:**
- Customer onboarding guide published
- Billing FAQ complete
- Troubleshooting guide ready
- Grafana dashboards operational
- Alerts configured and tested
- Alert response procedures documented

**Verification Commands:**
```bash
# Test Grafana dashboards
curl -s http://grafana.rsolv-staging.com/api/health

# Verify Prometheus metrics
curl -s http://prometheus.rsolv-staging.com/api/v1/query?query=up

# Test alert firing
# (Manually trigger alert conditions and verify delivery)
```

## Success Criteria (Launch Gates)

### Must Pass (Production Blockers)

- [x] **Integration Complete**: All RFCs 065-068 implemented (per ADR-032)
- [ ] **E2E Tests Passing**: 100% of E2E test suite green
- [ ] **Load Tests Passing**: All performance targets met
  - Customer onboarding < 5s P95
  - API response < 200ms P95
  - Webhook processing < 1s P95
- [ ] **Staging Stable**: 24+ hours uptime, no critical errors
- [ ] **Deployment Tested**: Runbook executed successfully on staging
- [ ] **Rollback Verified**: Rollback procedures tested and documented
- [ ] **Documentation Complete**:
  - Customer onboarding guide
  - Billing FAQ
  - Troubleshooting guide
  - Deployment runbook
- [ ] **Monitoring Operational**:
  - Grafana dashboards live
  - Alerts configured
  - Alert delivery tested

### Should Have (Recommended)

- [ ] OpenAPI specs 100% complete
- [ ] GitHub Marketplace approved
- [ ] Performance optimization opportunities identified
- [ ] Capacity planning for first 100 customers
- [ ] Support team trained on documentation

### Nice to Have (Post-Launch)

- Additional load test scenarios (burst traffic, long duration)
- Automated E2E test screenshots for demo
- Customer onboarding video
- Advanced monitoring (distributed tracing)

## Risk Management

### Critical Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| **Staging unstable** | High | Low | Daily monitoring, 24h stability gate |
| **Load tests fail** | High | Low | Already exceeded targets (ADR-032) |
| **Stripe production keys** | High | Medium | Test mode → prod mode migration plan |
| **Documentation incomplete** | Medium | Medium | Dedicated Friday focus |
| **Rollback untested** | High | Low | Thursday rollback testing |

### Mitigation Strategies

1. **Staging Instability**:
   - Daily health checks
   - Automated monitoring
   - 24-hour stability requirement
   - Rollback ready if issues found

2. **Load Test Failures**:
   - Already exceeded targets (12ms vs 5s target)
   - If regressions found, optimize or delay launch
   - No launch until targets met

3. **Stripe Production Migration**:
   - Document test → production key swap procedure
   - Verify webhook endpoints updated
   - Test with small real transactions first

4. **Documentation Gaps**:
   - Prioritize customer-facing docs (onboarding, FAQ)
   - Internal docs can be refined post-launch
   - Support team review on Friday

5. **Rollback Issues**:
   - Test rollback on staging Thursday
   - Document all rollback procedures
   - Feature flags as primary rollback mechanism

## Week 6 Transition (Production Launch)

### Pre-Launch Checklist (Week 6 Monday)

- [ ] All Week 5 success criteria met
- [ ] E2E tests passing
- [ ] Load tests passing
- [ ] Staging stable 24+ hours
- [ ] Documentation complete
- [ ] Monitoring operational
- [ ] Rollback tested
- [ ] Stripe production keys configured
- [ ] DNS/routing verified
- [ ] Support team briefed

### Launch Day (Week 6)

**Morning:**
- Final smoke tests on staging
- Review all success criteria
- Team synchronization call
- Go/no-go decision

**Launch Execution:**
1. Deploy to production (feature-flagged OFF)
2. Verify deployment health
3. Run production smoke tests
4. Enable feature flag gradually:
   - 10% traffic → monitor 1 hour
   - 50% traffic → monitor 2 hours
   - 100% traffic → full launch
5. Monitor metrics closely (first 24h)

**Post-Launch:**
- Daily monitoring reviews (first week)
- Customer feedback collection
- Performance tracking
- Issue triage and resolution

### Launch Announcement

**Channels** (per RFC-067):
- GitHub Marketplace (once approved)
- Mastodon (@rsolv@infosec.exchange)
- Bluesky, LinkedIn
- Dev.to blog post
- Hacker News Show HN
- Email list (if built)

**Messaging:**
- Automated security fix deployment
- Free trial (5-10 credits)
- Flexible pricing (PAYG $29, Pro $599/mo)
- GitHub Actions integration
- Production-ready (load tested, battle tested)

## Monitoring & Metrics

### Week 5 Metrics to Track

**System Health:**
- CPU utilization (target: < 50%)
- Memory usage (target: < 80%)
- Database connections (target: < 80% pool)
- Error rates (target: < 1%)
- Response times (P50, P95, P99)

**E2E Test Metrics:**
- Test pass rate (target: 100%)
- Test execution time
- Flaky test count (target: 0)

**Load Test Metrics:**
- Requests per second
- Latency percentiles
- Error rates
- Throughput
- Concurrent users supported

**Staging Stability:**
- Uptime percentage (target: 100% for 24h)
- Critical error count (target: 0)
- Warning count (acceptable: < 10/day)

### Week 6+ (Post-Launch) Metrics

**Business Metrics** (per RFC-064):
- Trial signups
- Trial → PAYG conversion (target: ≥15%)
- PAYG → Pro conversion
- Monthly churn rate (target: <5%)
- Customer Lifetime Value (target: >$300)

**Technical Metrics:**
- Production uptime (target: 99.9%)
- API response time (target: <200ms P95)
- Stripe success rate (target: >99%)
- Webhook processing success (target: >99.5%)

## Documentation Deliverables

### Customer-Facing (Public)

1. **Getting Started Guide**
   - Location: `docs/getting-started.md`
   - Audience: New customers
   - Content: Signup, API key, first scan

2. **Billing FAQ**
   - Location: `docs/billing-faq.md`
   - Audience: All customers
   - Content: Pricing, credits, subscriptions

3. **Troubleshooting Guide**
   - Location: `docs/troubleshooting.md`
   - Audience: Customers with issues
   - Content: Common problems and solutions

### Internal (Team)

1. **Deployment Runbook**
   - Location: `rsolv-infrastructure/DEPLOYMENT-PRODUCTION.md`
   - Audience: Engineering team
   - Content: Step-by-step deployment procedures

2. **Rollback Procedures**
   - Location: `rsolv-infrastructure/ROLLBACK-PROCEDURES.md`
   - Audience: Engineering team
   - Content: Emergency rollback steps

3. **Monitoring Guide**
   - Location: `docs/internal/MONITORING.md`
   - Audience: Engineering/support team
   - Content: Dashboard usage, alert response

4. **Support Escalation**
   - Location: `docs/internal/SUPPORT-ESCALATION.md`
   - Audience: Support team
   - Content: Issue triage, escalation paths

## Timeline Summary

| Day | Focus | Critical Tasks | Deliverable |
|-----|-------|----------------|-------------|
| **Monday** | Staging Stability | Deploy, monitor, baseline | 24h stability timer started |
| **Tuesday** | E2E Testing | Test suite, coverage, automation | E2E tests 100% passing |
| **Wednesday** | Load Testing | Performance validation, capacity | Load test results report |
| **Thursday** | Deployment | Runbooks, rollback testing | Deployment procedures verified |
| **Friday** | Support & Monitoring | Documentation, dashboards, alerts | Launch readiness complete |

## Communication Plan

**Daily Standups** (10 minutes):
- What's completed
- What's in progress
- Blockers or risks

**End-of-Day Updates** (via commit messages/ADRs):
- Progress on success criteria
- Issues encountered
- Decisions made

**Friday Review** (30 minutes):
- Week 5 completion status
- Go/no-go assessment for Week 6
- Risk review
- Launch readiness checklist

## Next Steps

### Immediate Actions (Start Monday)

1. **Deploy Latest Code to Staging**
   ```bash
   cd rsolv-infrastructure
   kubectl apply -f kubernetes/staging/
   ```

2. **Configure Monitoring Dashboards**
   - Verify Grafana access
   - Import dashboard templates
   - Configure data sources

3. **Review E2E Test Coverage**
   ```bash
   mix test test/e2e/
   ```

4. **Prepare Load Test Environment**
   ```bash
   # Verify k6 installed
   k6 version

   # Test staging endpoint
   curl -s https://api.rsolv-staging.com/health
   ```

### Week 5 Exit Criteria

**To proceed to Week 6 launch:**
- [x] All integration work complete (RFC-069, ADR-032)
- [ ] All Week 5 success criteria met
- [ ] All critical launch gates passed
- [ ] No production-blocking issues
- [ ] Team consensus on go/no-go

## References

### RFCs
- RFC-064: Billing & Provisioning Master Plan
- RFC-065: Automated Customer Provisioning
- RFC-066: Stripe Billing Integration
- RFC-067: GitHub Marketplace Publishing
- RFC-068: Billing Testing Infrastructure
- RFC-069: Integration Week

### ADRs
- ADR-032: Billing Integration Completion
- ADR-033: Stripe Webhook Processing Fixes
- ADR-025: Distributed Rate Limiting
- ADR-022: Credential Auto-Refresh

### Documentation
- `CLAUDE.md`: Project guidelines
- `docs/DEV_SETUP.md`: Development setup
- `rsolv-infrastructure/DEPLOYMENT.md`: Deployment guide

### Infrastructure
- Staging: https://api.rsolv-staging.com
- Production: https://api.rsolv.dev (not yet deployed)
- Grafana: (staging monitoring)
- Stripe Dashboard: (test mode)

## Appendix: Load Test Scripts

### Customer Onboarding Load Test
Location: `scripts/load-tests/onboarding-load-test.k6.js`

### Credential Vending Load Test
Location: `scripts/load-tests/credential-vending-load-test.k6.js`

### Webhook Load Test
Location: `scripts/load-tests/webhook-load-test.k6.js`

### Run All Tests
```bash
./scripts/load-tests/run-all-load-tests.sh staging
```

## Appendix: E2E Test Coverage Matrix

| Scenario | Test File | Status | Critical |
|----------|-----------|--------|----------|
| Trial Signup → First Fix | `customer_journey_test.exs` | ✅ Passing | Yes |
| Trial → PAYG Conversion | `customer_journey_test.exs` | ✅ Passing | Yes |
| Pro Subscription Creation | `customer_journey_test.exs` | ✅ Passing | Yes |
| Marketplace Installation | `customer_journey_test.exs` | ✅ Passing | No |
| Payment Method Addition | `customer_journey_test.exs` | ✅ Passing | Yes |
| Subscription Cancellation | `customer_journey_test.exs` | ✅ Passing | Yes |
| Webhook Processing | `webhook_integration_test.exs` | ✅ Passing | Yes |
| **Total Coverage** | **11 tests** | **100% passing** | **6/7 critical** |

---

**Status**: Active - Week 5 Production Preparation
**Next Review**: End of Week 5 (Go/No-Go for Week 6)
**Launch Target**: Week 6 (Nov 18-24, 2025)
