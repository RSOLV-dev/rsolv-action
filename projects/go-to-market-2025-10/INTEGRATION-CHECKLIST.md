# RFC-065-066-067-068 Integration Checklist

**Last Updated:** 2025-10-23
**Integration Lead:** Dylan
**Integration Week:** Monday Week 4 → Friday Week 4
**Public Launch:** Week 6 (pending launch gate criteria)

> **WORKING DOCUMENT:** This checklist is active during the integration project (Weeks 0-6). Upon completion, archive this directory to `archived_docs/billing-integration-2025-10/` and transfer permanent knowledge to relevant ADRs (ADR-025 through ADR-028).

---

## Integration Owner Responsibilities

### Dylan (Integration Lead)
- **Monitor:** All 4 RFCs (065, 066, 067, 068) for interface alignment throughout Weeks 1-3
- **Drive:** Monday Week 4 integration kickoff
- **Resolve:** Conflicts and blockers during Week 4 integration window
- **Own:** Production deployment Friday Week 4
- **Verify:** All integration ready criteria met before kickoff
- **Document:** Integration issues and resolutions in real-time

---

## RFC-065: Customer Onboarding - Integration Ready Criteria

### Testing & Quality
- [ ] All tests passing (`mix test`)
- [ ] No compilation warnings
- [ ] Credo checks passing (`mix credo`)
- [ ] Test coverage ≥80% for new code

### Core Functionality
- [ ] `CustomerOnboarding.provision_customer/1` working end-to-end
- [ ] API endpoint `POST /api/v1/customers/onboard` responding with 200/400/500
- [ ] Successfully calls `Billing.create_stripe_customer/1` (stub or real)
- [ ] Successfully calls `Billing.credit_customer/3` (stub or real)
- [ ] Database migrations applied cleanly (`mix ecto.migrate`)
- [ ] Rollback migrations working (`mix ecto.rollback`)

### OpenAPI Documentation
- [ ] OpenAPI spec for `/api/v1/customers/onboard` complete
- [ ] Request/response schemas validated
- [ ] Error responses documented (400, 401, 500)
- [ ] Regenerated spec (`mix openapi.spec.json`)

### Deployment
- [ ] Deployed to staging environment
- [ ] Demonstrable via Swagger UI or curl
- [ ] Environment variables documented in `.env.example`
- [ ] No hardcoded secrets or credentials

### Documentation
- [ ] ADR created: `ADRs/ADR-025-customer-onboarding-implementation.md`
- [ ] Integration notes added to this file (see Appendix)
- [ ] API changes communicated to RFC-067 (RSOLV-action) implementer

---

## RFC-066: Billing & Credits - Integration Ready Criteria

### Testing & Quality
- [ ] All tests passing (`mix test`)
- [ ] No compilation warnings
- [ ] Credo checks passing (`mix credo`)
- [ ] Test coverage ≥80% for new code
- [ ] Stripe webhook tests using `stripe-cli` fixtures

### Core Functionality
- [ ] Stripe integration working in test mode (API keys in `.env`)
- [ ] `Billing.create_stripe_customer/1` implemented and tested
- [ ] `Billing.credit_customer/3` implemented and tested
- [ ] Webhook endpoint `POST /webhooks/stripe` receiving events
- [ ] Webhook signature verification working
- [ ] Credit ledger tracking transactions correctly
- [ ] Database migrations applied cleanly

### Webhook Events Handled
- [ ] `customer.subscription.created`
- [ ] `customer.subscription.updated`
- [ ] `customer.subscription.deleted`
- [ ] `invoice.payment_succeeded`
- [ ] `invoice.payment_failed`

### OpenAPI Documentation
- [ ] OpenAPI spec for billing endpoints complete
- [ ] Credit ledger endpoints documented
- [ ] Webhook endpoint documented (even if internal)

### Deployment
- [ ] Deployed to staging environment
- [ ] Stripe test mode connected to staging
- [ ] Webhook endpoint publicly accessible (ngrok or staging domain)
- [ ] Tested end-to-end with Stripe test cards
- [ ] `support@rsolv.dev` email configured for receipts

### Documentation
- [ ] ADR created: `ADRs/ADR-026-billing-credits-implementation.md`
- [ ] Integration notes added to this file (see Appendix)
- [ ] Billing flow diagrams updated
- [ ] Customer-facing credit documentation drafted

---

## RFC-067: GitHub Action Polish - Integration Ready Criteria

### Testing & Quality
- [ ] All tests passing (`npm run test:memory`)
- [ ] No TypeScript errors (`npx tsc --noEmit`)
- [ ] No ESLint warnings
- [ ] Integration tests passing with live staging API (if `RUN_INTEGRATION=true`)

### Core Functionality
- [ ] SCAN phase working with NodeGoat
- [ ] VALIDATE phase working with RailsGoat
- [ ] MITIGATE phase creating PRs successfully
- [ ] New branding elements displaying correctly
- [ ] README rendering correctly on GitHub

### Documentation Updates
- [ ] README updated with:
  - New hero section
  - Feature highlights
  - Getting started guide
  - Screenshots/GIFs of action in use
- [ ] `action.yml` updated with:
  - New branding (icon, color)
  - Accurate description
  - Input/output documentation

### Testing with Real Repos
- [ ] Tested with NodeGoat (Node.js vulnerabilities)
- [ ] Tested with RailsGoat (Ruby vulnerabilities)
- [ ] Verified issue creation, branch creation, PR creation
- [ ] Confirmed credit consumption via staging API

### Marketplace Preparation
- [ ] Marketplace submission materials prepared (DON'T SUBMIT until Week 4):
  - Action name and description finalized
  - Screenshots/demo GIFs ready
  - Categories selected
  - Pricing tier decided (free during beta)
- [ ] GitHub App permissions verified
- [ ] Rate limit handling tested

### Documentation
- [ ] ADR created: `ADRs/ADR-027-github-action-polish-implementation.md`
- [ ] Integration notes added to this file (see Appendix)
- [ ] Version bump strategy documented (post-launch)

---

## RFC-068: Testing Standards - Integration Ready Criteria

### Infrastructure
- [ ] Docker Compose test infrastructure running
- [ ] PostgreSQL test database seeding reliably
- [ ] Redis test instance working
- [ ] Test environment variables documented

### Factory Traits
- [ ] Factory traits created for:
  - Users (admin, staff, customer, enterprise)
  - Organizations (free, pro, enterprise)
  - Subscriptions (trial, active, canceled, past_due)
  - API keys (valid, expired, revoked)
  - Vulnerabilities (high/medium/low severity)
  - Fix attempts (pending, completed, failed)
- [ ] All traits tested and working
- [ ] Documentation in `test/support/factory.ex` or README

### Staging Environment
- [ ] Staging environment deployed and stable
- [ ] Environment variables properly configured
- [ ] Database migrations applied
- [ ] Seed data loaded
- [ ] SSL/TLS working
- [ ] Monitoring configured

### Load Testing
- [ ] k6 load test scripts written for:
  - Authentication endpoints
  - AST analysis endpoints
  - Vulnerability detection endpoints
  - Credit consumption endpoints
- [ ] Baseline performance metrics captured
- [ ] Load test results documented

### Monitoring & Observability
- [ ] Grafana dashboards created for:
  - API request rates
  - Error rates (4xx, 5xx)
  - Response times (p50, p95, p99)
  - Database query performance
  - Credit consumption rates
- [ ] Alerts configured for critical metrics
- [ ] Log aggregation working (CloudWatch or equivalent)

### Documentation
- [ ] ADR created: `ADRs/ADR-028-testing-standards-implementation.md`
- [ ] Load testing guide in `docs/LOAD-TESTING.md`
- [ ] Factory usage guide in `test/support/README.md`
- [ ] Staging environment runbook in `docs/STAGING.md`

---

## Week 4 Integration Day-by-Day Plan

### Monday: Integration Kickoff
- [ ] Integration lead (Dylan) confirms all 4 RFCs meet criteria above
- [ ] Review integration checklist and dependencies
- [ ] Identify any last-minute blockers

### Tuesday-Wednesday: Integration Work
- [ ] Wire RFC-065 (onboarding) to RFC-066 (billing)
- [ ] Test end-to-end flow: signup → Stripe → credits
- [ ] Wire RFC-067 (action) to staging API
- [ ] Run load tests from RFC-068 against integrated system
- [ ] Fix integration bugs as discovered

### Thursday: E2E Testing & Validation
- [ ] Run full E2E test suite (to be written during integration)
- [ ] Verify all 4 RFCs working together
- [ ] Smoke test on staging with real GitHub Action
- [ ] Security review of integrated system
- [ ] Performance validation (load tests green)

### Friday: Production Deployment
- [ ] Final staging verification
- [ ] Deploy to production
- [ ] Smoke test production (without announcing publicly)
- [ ] Monitor for 2 hours post-deployment
- [ ] Rollback plan ready (tested Thursday)

---

## Week 6 Launch Gate Criteria

**Do NOT proceed to public launch unless ALL criteria met:**

### Technical Readiness
- [ ] E2E tests passing (implemented Week 4-5, must be green)
- [ ] Staging stable for 24+ hours (no critical bugs)
- [ ] Production deployed and stable for 24+ hours
- [ ] Rollback procedure tested successfully on staging
- [ ] No known P0 or P1 bugs

### Customer Readiness
- [ ] 10+ committed beta testers identified and onboarded
- [ ] Beta testing feedback incorporated (Week 5 priority bugs fixed)
- [ ] Customer support email `support@rsolv.dev` working and monitored
- [ ] Documentation site `docs.rsolv.dev` live and complete
- [ ] Billing disputes process documented and tested

### Marketing & Communications
- [ ] Social media accounts configured:
  - [ ] Mastodon (@rsolv@infosec.exchange)
  - [ ] Twitter/X
  - [ ] LinkedIn company page
- [ ] Launch blog post written and reviewed
- [ ] GitHub Action marketplace listing approved
- [ ] Press kit prepared (for IndieHackers, dev.to, etc.)

### Operational Readiness
- [ ] On-call rotation defined (even if just Dylan initially)
- [ ] Incident response playbook created
- [ ] Monitoring and alerting verified working
- [ ] Backup and restore procedures tested
- [ ] Rate limiting and abuse prevention tested

### Legal & Compliance
- [ ] Terms of Service finalized
- [ ] Privacy Policy finalized
- [ ] GDPR compliance verified (data export, deletion)
- [ ] Stripe billing terms accepted

---

## Integration Blockers & Escalation

### Blocker Severity Levels

**P0 (Critical - Blocks Integration):**
- Interface contracts broken between RFCs
- Critical bugs in RFC implementation
- Staging environment down
- Missing required functionality

**P1 (High - Requires Immediate Attention):**
- Test failures in integration scenarios
- Performance issues discovered in load testing
- Security vulnerabilities identified
- Documentation gaps preventing integration

**P2 (Medium - Should Fix Before Launch):**
- Minor bugs in non-critical paths
- UI/UX issues
- Documentation improvements needed

**P3 (Low - Can Fix Post-Launch):**
- Nice-to-have features
- Code quality improvements
- Non-critical performance optimizations

### Escalation Path
1. **RFC Implementer:** Try to resolve within their RFC scope
2. **Integration Lead (Dylan):** Coordinate cross-RFC resolution
3. **Scope Reduction:** If necessary, defer P2/P3 to post-launch

---

## Success Metrics

### Week 4 Integration Success
- All 4 RFCs deployed to production
- E2E tests passing
- No P0 or P1 bugs remaining
- Staging stable for 24+ hours
- Ready for Week 5 beta testing

### Week 6 Launch Success
- 10+ beta customers successfully onboarded
- GitHub Action successfully running on 5+ repos
- No critical production incidents
- Customer feedback positive (NPS ≥ 30)
- Ready to announce publicly

---

## Appendix: Integration Contracts & Specifications

**Status**: Defined Week 0
**Purpose**: Interface contracts between RFCs 065, 066, 067, 068

---

### A.1 Data Type Conventions

**CRITICAL**: All implementers MUST follow these exact conventions:

#### Subscription Type (Pricing Tier)
- **Field**: `subscription_type`
- **Type**: STRING (not atom)
- **Values**: `"trial"` | `"pay_as_you_go"` | `"pro"`
- **Default**: `"trial"`
- **Migration**: Rename `subscription_plan` → `subscription_type`

#### Subscription State (Stripe Lifecycle)
- **Field**: `subscription_state`
- **Type**: STRING or `nil`
- **Values**: `nil` (trial/PAYG), `"active"`, `"past_due"`, `"canceled"`, `"unpaid"`, `"incomplete"`, `"paused"`
- **Default**: `nil`
- **Migration**: Rename `subscription_status` → `subscription_state`

#### Date/Time Format
- **Type**: `:utc_datetime` (Ecto)
- **Convention**: All timestamps in UTC

#### Credit Balance
- **Field**: `credit_balance`
- **Type**: INTEGER
- **Unit**: Number of fixes (1 credit = 1 fix)
- **Default**: `0`

---

### A.2 RFC-065 ↔ RFC-066 Interface Contract

#### Function Signatures (RFC-066 MUST implement)

**Credit Customer**:
```elixir
@spec credit_customer(Customer.t(), pos_integer(), keyword()) ::
  {:ok, CreditTransaction.t()} | {:error, term()}

# Usage:
Billing.credit_customer(customer, 5, source: "trial_signup")
```

**Parameters**:
- `customer`: Customer struct
- `amount`: Positive integer credits
- `opts`:
  - `:source` (required) - `"trial_signup"` | `"trial_billing_added"` | `"pro_subscription_payment"` | `"purchased"` | `"admin_adjustment"`
  - `:metadata` (optional) - Additional context map

**Add Payment Method**:
```elixir
@spec add_payment_method(Customer.t(), String.t(), keyword()) ::
  {:ok, Customer.t()} | {:error, term()}

# Usage:
Billing.add_payment_method(customer, "pm_1234...", consent_given: true)
```

**Track Fix Deployed**:
```elixir
@spec track_fix_deployed(Customer.t(), Fix.t()) ::
  {:ok, CreditTransaction.t()} | {:ok, :charged_and_consumed} | {:error, term()}

# Behavior:
# - Has credits → Consume 1 credit
# - No credits, no billing → {:error, :no_billing_info}
# - No credits, has billing (PAYG) → Charge $29, credit 1, consume 1
# - No credits, has billing (Pro) → Charge $15, credit 1, consume 1
```

#### Customer Fields Required by RFC-066

RFC-065 migration MUST ensure these fields exist:
```elixir
%Customer{
  credit_balance: integer(),           # REQUIRED
  subscription_type: string(),         # REQUIRED - "trial" | "pay_as_you_go" | "pro"
  subscription_state: string() | nil,  # REQUIRED - Stripe state or nil
  stripe_customer_id: string() | nil,  # REQUIRED - When billing added
  billing_consent_given: boolean(),    # REQUIRED - User consent checkbox
  billing_consent_at: DateTime.t() | nil,
  subscription_cancel_at_period_end: boolean()  # REQUIRED
}
```

---

### A.3 Provisioning Flow with Credits

#### Complete Signup Flow
```elixir
# 1. Create customer (RFC-065)
{:ok, customer} = Customers.create_customer(%{
  email: "user@example.com",
  name: "Jane Developer",
  subscription_type: "trial",  # ✅ STRING
  subscription_state: nil,
  credit_balance: 0
})

# 2. Credit signup bonus (RFC-066)
{:ok, _txn} = Billing.credit_customer(customer, 5, source: "trial_signup")
# customer.credit_balance == 5

# 3. Generate API key (RFC-065)
{:ok, api_key_data} = ApiKeys.create_for_customer(customer)

# 4. Send welcome email (RFC-065, async via Oban)
EmailSequence.start_early_access_onboarding_sequence(
  customer.email,
  customer.name,
  api_key_data.raw_key
)
```

#### Add Billing Info Flow
```elixir
# User adds payment method (RFC-066)
{:ok, updated_customer} = Billing.add_payment_method(
  customer,
  "pm_1234...",
  consent_given: true
)
# updated_customer.credit_balance == 10  (5 signup + 5 billing)
# updated_customer.stripe_customer_id == "cus_..."
```

#### Subscribe to Pro Flow
```elixir
# User subscribes (RFC-066)
{:ok, subscription} = Billing.subscribe_to_pro(customer)
# Creates Stripe subscription ($599/month)
# Charges immediately
# Webhook processes invoice.paid → credits +60
# customer.subscription_type == "pro"
# customer.subscription_state == "active"
# customer.credit_balance == 70  (10 from trial + 60 from Pro)
```

---

### A.4 Worker Signatures

#### StripeRetryWorker (RFC-066 creates)
```elixir
# File: lib/rsolv/workers/stripe_retry_worker.ex
defmodule Rsolv.Workers.StripeRetryWorker do
  use Oban.Worker,
    queue: :stripe_retries,
    max_attempts: 3

  @impl Oban.Worker
  def perform(%Oban.Job{args: args}) do
    # args = %{
    #   "operation" => "create_customer" | "attach_payment_method" | "create_subscription",
    #   "customer_id" => binary_id(),
    #   "params" => map()
    # }
  end
end
```

#### EmailRetryWorker (Decision: Reuse Existing)
**DO NOT create** - Reuse existing `EmailWorker` which already has `max_attempts: 3`

---

### A.5 Admin Module Structure

**Single file with namespaced functions:**

```elixir
# File: lib/rsolv/admin.ex
defmodule Rsolv.Admin do
  # RFC-065 functions
  defdelegate reset_credits(email, amount), to: Rsolv.Admin.CustomerAdmin
  defdelegate resend_welcome(email), to: Rsolv.Admin.CustomerAdmin

  # RFC-066 functions
  defdelegate cancel_subscription(email, opts \\ []), to: Rsolv.Admin.BillingAdmin
  defdelegate adjust_credit_balance(email, amount, reason), to: Rsolv.Admin.BillingAdmin
end
```

**Implementation modules:**
- `lib/rsolv/admin/customer_admin.ex` - RFC-065 creates
- `lib/rsolv/admin/billing_admin.ex` - RFC-066 creates

---

### A.6 Migration Coordination

**CRITICAL**: Migrations MUST run in this order:

1. **RFC-065 migration** - Add provisioning fields
2. **RFC-066 migration** - Rename subscription fields + add billing tables

#### RFC-065 Responsibilities
```elixir
# Add provisioning fields only
alter table(:customers) do
  add :auto_provisioned, :boolean, default: false
  add :wizard_preference, :string, default: "auto"
  add :first_scan_at, :utc_datetime
end

# DO NOT rename subscription_plan/subscription_status
# RFC-066 will handle this
```

#### RFC-066 Responsibilities
```elixir
# CRITICAL: Rename subscription fields first
rename table(:customers), :subscription_plan, to: :subscription_type
rename table(:customers), :subscription_status, to: :subscription_state

# Then add billing fields
alter table(:customers) do
  add :credit_balance, :integer, default: 0, null: false
  add :stripe_customer_id, :string
  add :billing_consent_given, :boolean, default: false, null: false
  # ... other billing fields
end

# Create credit_transactions table
create table(:credit_transactions, primary_key: false) do
  add :id, :binary_id, primary_key: true
  add :customer_id, references(:customers, on_delete: :delete_all), null: false
  add :amount, :integer, null: false
  add :balance_after, :integer, null: false
  add :source, :string, null: false
  add :metadata, :map, default: %{}
  timestamps(type: :utc_datetime)
end

# Create billing_events table (webhook idempotency)
create table(:billing_events, primary_key: false) do
  add :id, :binary_id, primary_key: true
  add :stripe_event_id, :string, null: false
  add :event_type, :string, null: false
  add :customer_id, references(:customers, on_delete: :nilify_all)
  add :amount_cents, :integer
  add :metadata, :map, default: %{}
  timestamps(type: :utc_datetime)
end

create unique_index(:billing_events, [:stripe_event_id])
```

---

### A.7 Integration Testing Contract

**Required integration tests (RFC-069 Week 4):**

```elixir
# Complete signup flow
test "signup credits customer correctly" do
  # Verify subscription_type: "trial", credit_balance: 5
end

# Add billing flow
test "adding billing info credits +5" do
  customer = create_trial_customer()  # credit_balance: 5
  # After: credit_balance: 10, stripe_customer_id present
end

# Pro subscription flow
test "Pro subscription credits +60 on invoice.paid" do
  customer = create_customer_with_billing()  # credit_balance: 10
  # After: credit_balance: 70, subscription_type: "pro"
end

# Fix deployment flows
test "fix deployment consumes credit when available" do
  # credit_balance: 5 → 4
end

test "fix deployment charges PAYG when no credits" do
  # Charges $29, credits 1, consumes 1, balance stays 0
end

test "subscription cancellation preserves credits" do
  # Pro → PAYG, credits preserved, pricing reverted
end
```

---

### A.8 API Response Format

**Standardized customer object:**
```json
{
  "customer": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "name": "Jane Developer",
    "credit_balance": 10,
    "subscription_type": "trial",
    "subscription_state": null,
    "stripe_customer_id": "cus_abc123",
    "billing_consent_given": true,
    "inserted_at": "2025-10-23T12:00:00Z",
    "updated_at": "2025-10-24T08:30:00Z"
  }
}
```

---

### A.9 Error Handling Contract

**Standard error responses:**

**Business Logic Errors (400)**:
```json
{
  "error": "insufficient_credits",
  "message": "No credits available. Please add billing information.",
  "credit_balance": 0,
  "has_billing_info": false
}
```

**Validation Errors (422)**:
```json
{
  "errors": {
    "email": ["has already been taken"],
    "password": ["must contain at least one uppercase letter"]
  }
}
```

---

### A.10 Performance & Load Testing Results
_To be filled during Week 4 integration:_
- Baseline metrics from RFC-068
- Bottlenecks discovered
- Optimizations applied
- Final performance numbers

---

### A.11 Security Considerations
_To be filled during Week 4 integration:_
- Webhook signature verification implementation
- API key rotation procedures
- Rate limiting enforcement results
- PCI compliance validation

---

## Post-Launch: Archive Instructions

When integration project completes (post-Week 6 launch):

1. **Archive this project directory:**
   ```bash
   mv projects/billing-integration-2025-10 archived_docs/billing-integration-2025-10
   ```

2. **Transfer knowledge to ADRs:**
   - Integration decisions → ADR-025, ADR-026, ADR-027, ADR-028
   - Interface contracts → Relevant ADRs
   - Performance results → ADR-028 (testing standards)
   - Security considerations → Relevant ADRs

3. **Update permanent docs:**
   - API documentation (OpenAPI specs)
   - Developer guides (`docs/`)
   - Deployment runbooks (`rsolv-infrastructure/DEPLOYMENT.md`)

4. **Delete temporary content** from archived directory that was only useful during active integration.
