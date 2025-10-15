# RFC-065: Automated Customer Provisioning

**Status**: Draft
**Created**: 2025-10-12
**Timeline**: 3 weeks
**Dependencies**: None (can start immediately)

## Quick Start

**Current State**: Manual provisioning after signup
**Files to Modify**:
- `lib/rsolv_web/live/early_access_live.ex` - Signup form
- `lib/rsolv/customers.ex` - Customer context
- `lib/rsolv/customers/customer.ex` - Model (has fields)
- `lib/rsolv/customers/api_key.ex` - Key generation (working)

**Trial Limits**: 10 free fixes (update from current 5)

## Summary

Transform manual customer provisioning into automated self-service. When customers sign up, instantly create account, generate API key, and provide dashboard access.

## Problem

Current manual process doesn't scale:
1. Admin receives signup notification
2. Admin manually creates customer
3. Admin generates API key
4. Admin emails credentials
5. Customer manually configures GitHub

**Impact**: Hours of delay, poor first impression, operational burden

## Solution

### Automated Flow
```
Signup → Validate → Create Customer → Generate Key → Send Email → Dashboard Access
         ↓ (fail)
      Rate Limited/Invalid → Reject with message
```

### Core Implementation

```elixir
defmodule Rsolv.Provisioning do
  def provision_from_signup(params) do
    with {:ok, validated} <- validate_signup(params),
         {:ok, customer} <- create_customer(validated),
         {:ok, api_key} <- create_api_key(customer),
         {:ok, _} <- send_welcome_email(customer, api_key) do
      {:ok, customer}
    end
  end

  defp create_customer(params) do
    %{
      email: params.email,
      name: params.name,
      subscription_plan: "trial",
      trial_fixes_limit: 10,
      trial_fixes_used: 0,
      auto_provisioned: true
    }
    |> Customers.create_customer()
  end
end
```

### Customer Dashboard

New LiveView at `/dashboard`:
- View/regenerate API keys
- Usage stats (X/10 fixes used)
- Download GitHub workflow file
- Setup instructions
- Recent fix attempts

### Database Changes

```sql
ALTER TABLE customers
  ADD COLUMN auto_provisioned BOOLEAN DEFAULT FALSE,
  ADD COLUMN onboarding_completed_at TIMESTAMP;

CREATE TABLE provisioning_events (
  id UUID PRIMARY KEY,
  customer_id INTEGER REFERENCES customers(id),
  event_type VARCHAR(50),
  status VARCHAR(20),
  created_at TIMESTAMP DEFAULT NOW()
);
```

## TDD Implementation Tasks

### Week 1: Core Provisioning (RED-GREEN-REFACTOR)
- [ ] Write failing test: "provisions customer from valid signup"
- [ ] Build provisioning pipeline in `lib/rsolv/provisioning.ex`
- [ ] Write failing test: "rejects disposable email domains"
- [ ] Add email validation (block disposable domains)
- [ ] Write failing test: "enforces rate limits"
- [ ] Implement rate limiting (3 per email/day, 10 per IP/hour)
- [ ] Write failing test: "generates unique secure API keys"
- [ ] Generate secure API keys automatically
- [ ] Create provisioning_events tracking table

### Week 2: Self-Service Dashboard (TDD)
- [ ] Write test: "dashboard requires authentication"
- [ ] Create `/dashboard` LiveView
- [ ] Write test: "can regenerate API key"
- [ ] API key management UI (view, regenerate, revoke)
- [ ] Write test: "displays usage statistics"
- [ ] Usage display with progress bar (X/10 fixes)
- [ ] Write test: "generates valid GitHub workflow"
- [ ] One-click GitHub workflow download
- [ ] Recent fix attempts table
- [ ] Account settings page

### Week 3: Onboarding & Polish (TDD)
- [ ] Write test: "sends welcome email on provisioning"
- [ ] Welcome email with API key and setup link
- [ ] Write test: "shows setup wizard for new users"
- [ ] Setup wizard on first dashboard visit
- [ ] Write test: "schedules follow-up emails"
- [ ] Follow-up emails (24h, 72h, 1 week)
- [ ] Write test: "retries on transient failures"
- [ ] Error handling and retry logic
- [ ] Admin override capabilities
- [ ] Monitoring and alerting

## Testing Requirements

### Unit Tests
```elixir
test "provisions customer from valid signup"
test "rejects disposable emails"
test "enforces rate limits"
test "handles duplicate signups gracefully"
test "generates unique secure API keys"
```

### Integration Tests
```elixir
test "complete signup to dashboard flow"
test "API key works immediately after provisioning"
test "onboarding emails delivered in sequence"
```

### Load Tests
- 100 concurrent signups
- Rate limiting effectiveness
- Database connection pooling

## Security Measures

1. **Email Validation**: Block disposable domains, verify format
2. **Rate Limiting**: Per-email and per-IP limits
3. **API Keys**: Cryptographically secure, hashed in DB
4. **Dashboard**: Session-based auth, CSRF protection

## Success Metrics

- **Provisioning Time**: < 5 seconds
- **Success Rate**: > 99%
- **Dashboard Activation**: > 80% within 24h
- **First Scan**: > 60% within 24h
- **Support Tickets**: < 5% of signups

## Risks & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| Spam signups | High | Rate limiting, CAPTCHA if needed |
| Email delivery | Medium | Fallback providers, retry logic |
| Provisioning failures | High | Admin alerts, manual fallback |

## Rollout Plan

1. **Internal Testing**: Team dogfooding (2 days)
2. **Beta Users**: 10 selected customers (3 days)
3. **General Availability**: All new signups (ongoing)

## Future Enhancements

- OAuth (GitHub/GitLab)
- Team invitations
- CLI provisioning
- Webhook for signup events

## Next Steps

1. Create `lib/rsolv/provisioning.ex` module
2. Update signup form to call provisioning
3. Deploy to staging for testing