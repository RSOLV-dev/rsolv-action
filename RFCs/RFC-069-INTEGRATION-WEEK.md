# RFC-069: Integration Week Plan

**Status**: Draft
**Created**: 2025-10-12
**Timeline**: Week 4 (Nov 4-10, 2025)
**Prerequisites**: RFCs 065-068 at 80% complete

## Summary

Critical week where four parallel workstreams (Provisioning, Billing, Marketplace, Testing) converge into unified billing system. Highest-risk phase requiring careful daily coordination.

## Pre-Integration Checklist

### Must Complete by End of Week 3

**Provisioning (RFC-065)**:
- [ ] Automated provisioning working
- [ ] Customer dashboard live
- [ ] API key generation functional

**Billing (RFC-066)**:
- [ ] Stripe integration complete
- [ ] Webhook endpoint responding
- [ ] Subscription creation working

**Marketplace (RFC-067)**:
- [ ] Submission complete
- [ ] Documentation ready

**Testing (RFC-068)**:
- [ ] Test infrastructure running
- [ ] Staging environment deployed

## Integration Data Flow

```
Signup → Provisioning → Stripe Customer → API Key → Dashboard
            ↓               ↓                ↓
        Database     Stripe Service    Email Service
            ↓               ↓                ↓
        Webhooks ← Usage Tracking ← GitHub Action
```

## Data Contracts

### Provisioning → Billing
```elixir
%{
  customer_id: integer,
  email: string,
  name: string,
  plan: :trial | :payg | :teams
}
```

### Billing → Provisioning
```elixir
%{
  stripe_customer_id: string,
  subscription_status: string,
  can_use_service: boolean,
  current_usage: integer
}
```

## Daily Integration Plan (TDD Focus)

### Monday: Connect Systems
**Morning**:
- 9:00 AM - Kickoff meeting
- Write integration tests FIRST (RED)
- Deploy all branches to staging
- Fix interface contracts until tests pass (GREEN)

**Afternoon**:
- Refactor interfaces (REFACTOR)
- Verify data flow with tests
- Update integration tests
- 4:00 PM - Day review

**Tests to Write First**:
```elixir
test "provisioning creates billing customer"
test "billing returns correct status"
test "usage events accepted"
test "dashboard queries work"
```

### Tuesday: Happy Path (TDD)
**Goal**: Complete customer journey works

**Write Tests First**:
```elixir
test "trial signup to first fix"
test "trial to paid conversion"
test "marketplace installation"
test "payment method addition"
```
Then implement until all pass.

### Wednesday: Error Handling (TDD)
**Goal**: System handles failures gracefully

**Write Failure Tests First**:
```elixir
test "recovers from stripe API failures"
test "retries payment failures"
test "handles duplicate webhooks"
test "prevents race conditions"
```
Then add error handling until tests pass.

### Thursday: Load Testing
**Goal**: System performs under load

**Tests**:
```elixir
test "100 concurrent signups"
test "1000 webhooks/minute"
test "API rate limits hold"
test "memory usage stable"
```

### Friday: Beta Preparation
**Morning**:
- Final test run
- Deploy to production (feature-flagged)
- Verify monitoring

**Afternoon**:
- Beta customer prep
- Support documentation
- Launch review

## Critical Integration Points

### 1. Signup → Billing
```elixir
def provision_customer(params) do
  with {:ok, customer} <- create_customer(params),
       {:ok, stripe_id} <- Billing.create_stripe_customer(customer),
       {:ok, _} <- update_customer(customer, stripe_id) do
    {:ok, customer}
  end
end
```

### 2. Payment → Status Update
```elixir
def add_payment_method(customer, token) do
  with {:ok, _} <- Stripe.attach_payment(customer, token),
       {:ok, _} <- update_customer_status(customer, "active") do
    {:ok, :payment_added}
  end
end
```

### 3. Usage → Billing
```elixir
def track_fix(customer, fix) do
  with :ok <- check_limits(customer),
       {:ok, _} <- record_usage(customer, 1),
       {:ok, _} <- maybe_charge(customer) do
    {:ok, :tracked}
  end
end
```

### 4. Phase Completion → Usage Tracking (RFC-060-AMENDMENT-001 Integration)

```elixir
# PhaseDataClient receives completion signal from GitHub Action
# This is the integration point where validation/mitigation phases connect to billing
def handle_phase_completion(%{phase: :mitigate, status: :success} = result) do
  customer = Customers.get_customer(result.customer_id)

  # This triggers billing for the successful fix
  Billing.track_fix_deployed(customer, result)
end

# Alternative implementation via PubSub:
def handle_info({:phase_completed, phase_result}, state) do
  if billable_event?(phase_result) do
    process_billing(phase_result)
  end
  {:noreply, state}
end

defp billable_event?(%{phase: :mitigate, status: :success}), do: true
defp billable_event?(_), do: false
```

**Integration Notes:**

1. **Test Integration API is used EARLIER in VALIDATE phase:**
   - POST /api/v1/test-integration/analyze (scores test files)
   - POST /api/v1/test-integration/generate (integrates tests)
   - By the time `track_fix_deployed()` is called, tests have already been created and run

2. **Billing only cares about FINAL deployment success:**
   - Billing doesn't care HOW tests were generated (AST vs string matching)
   - Billing doesn't care WHERE tests are located (spec/ vs .rsolv/tests/)
   - Billing only cares: "Did a fix get successfully deployed?"

3. **PhaseDataClient acts as the integration hub:**
   - Receives completion signals from GitHub Action
   - Stores phase results in database
   - Emits events that trigger billing
   - Provides loose coupling between phases and billing

4. **Event Flow:**
   ```
   GitHub Action → PhaseDataClient → Phase Completion Event → Billing.track_fix_deployed()
   ```

**Why This Matters:**
This clarifies that billing happens in response to phase completion EVENTS (received via PhaseDataClient), not directly from the GitHub Action. The test integration API (RFC-060-AMENDMENT-001) and billing (RFC-066) are loosely coupled through the event-driven phase completion mechanism. Changes to validation (like test location or integration method) don't affect the billing interface.

## Rollback Strategy

### Feature Flags
```elixir
if FunWithFlags.enabled?(:auto_provisioning) do
  auto_provision(customer)
else
  manual_queue(customer)
end
```

### Database Backups
```bash
# Before integration
pg_dump production > backup_pre_integration.sql

# Daily backups
pg_dump production > backup_day_${DAY}.sql
```

### Kill Switches
```yaml
# runtime.exs
config :rsolv,
  billing_enabled: env("BILLING_ENABLED") != "false",
  auto_provision: env("AUTO_PROVISION") != "false"
```

## Risk Areas & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| Webhook race conditions | High | Queue and process async |
| Payment during provisioning | Medium | Lock during provisioning |
| API validation performance | High | Cache with 60s TTL |
| Interface mismatches | High | Day 1 validation tests |

## Communication Plan

### Daily Standups
- 9:00 AM - Morning sync (15 min)
- 1:00 PM - Quick check (5 min)
- 4:00 PM - Day review (15 min)

### Escalation Path
```
Issue → Team Lead (5m) → Integration Lead (15m) → CTO (30m)
```

### Channels
- Slack: #billing-integration
- Status: integration.rsolv.dev
- Email: Daily summary at 5 PM

## Success Criteria

### Must Have (Beta Blockers)
- [ ] Automated signup → API key flow
- [ ] Payment method addition works
- [ ] Subscription creation successful
- [ ] Usage tracking accurate
- [ ] All tests passing (>90%)
- [ ] Staging stable for 24 hours

### Should Have
- [ ] Load tests pass
- [ ] Monitoring complete
- [ ] Rollback tested

## Week 4 Checklist

### Monday
- [ ] All systems connected
- [ ] Interface tests pass
- [ ] Data flows correctly

### Tuesday
- [ ] Happy path works end-to-end
- [ ] Customer journey smooth

### Wednesday
- [ ] Error handling verified
- [ ] Recovery procedures work

### Thursday
- [ ] Load tests pass
- [ ] Performance acceptable

### Friday
- [ ] Beta ready
- [ ] Monitoring active
- [ ] Documentation complete

## Next Steps

### Week 3 (This Week)
1. Review RFC with all teams
2. Ensure prerequisites met
3. Set up integration environment

### Monday Morning
1. 9 AM all-hands kickoff
2. Deploy all branches
3. Begin interface validation