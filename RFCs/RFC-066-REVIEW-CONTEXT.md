# RFC-066 Review Context Handoff

**Date**: 2025-10-20
**Purpose**: Context transfer for RFC-066 (Stripe Billing) review continuation
**Status**: Ready for Dylan's notes, then revision

## Important: Next Session Workflow

1. **FIRST:** Dylan will provide his own review notes on RFC-066
2. **THEN:** Review both sets of notes together
3. **FINALLY:** Revise RFC-066 addressing both reviews

**DO NOT immediately start revising RFC-066 in the next session!**

---

## Completed Work Summary

### RFC-065 Comprehensive Revision (DONE ✅)
- Updated with all feedback from 13 Q&A clarifications
- API-first architecture (REST endpoint + self-contained module)
- SHA256 API key hashing (Phoenix best practices)
- Comprehensive Ecto migrations with safety checklist
- Error handling via Ecto.Multi + Oban retry
- Admin overrides via RPC-compatible module
- Mermaid sequence diagram + ASCII flow
- Complete TDD implementation tasks (RED-GREEN-REFACTOR)

**Commits:**
- `6d2a6489` - RFC-065 comprehensive revision
- `b7c82a05` - RFC-070 through RFC-076 skeletons
- `07707673` - Removed RFC-073 (multi-user conflated with pricing)

### Related RFCs Updated (DONE ✅)
- RFC-064: No changes needed (coordination level)
- RFC-066: Trial limit model added to Quick Start
- RFC-068: Test scenarios updated for 5+5 trial model
- RFC-069: No changes needed (generic integration)
- RFC-INDEX: Updated with RFC-072, 074, 075, 076 (073 removed)

---

## Key Architectural Decisions

### 1. Trial Limit Model (CRITICAL)
**Decision:** 5 free fixes on signup → +5 when billing added (total 10) → PAYG with explicit opt-in

```
Signup:
  - subscription_plan: "trial"
  - trial_fixes_limit: 5
  - trial_fixes_used: 0

Add Payment Method:
  - trial_fixes_limit: 10 (increment by 5)
  - stripe_customer_id: "cus_xxx"
  - Still on trial plan!

After 10 Fixes:
  - Block next fix
  - Require explicit opt-in
  - If confirmed: payg_confirmed: true, subscription_plan: "pay_as_you_go"
  - Then charge $15/fix
```

### 2. "Teams" = Pricing Tier, NOT Multi-User
**Confirmed:** "Teams" is just a volume discount subscription plan.
- $499/month for 60 fixes ($8.32/fix average)
- Still single-user account
- No shared logins needed (usage-priced, we don't care)
- Multi-user features wanted "eventually" but way down the line (no timeline)

**RFC-073 REMOVED** because it conflated pricing with multi-user features.

### 3. API-First Architecture
**Pattern established in RFC-065:**
- Self-contained modules with clear input/output contracts
- No web dependencies (conn, Phoenix-specific code)
- Callable from: REST API, LiveView, admin RPC, future integrations
- Returns `{:ok, result} | {:error, reason}` tuples

**RFC-066 should follow same pattern.**

### 4. Ecto Migrations Required (CRITICAL)
**Rule:** ALL database changes via Ecto migrations. NO raw SQL.

**Example from RFC-065:**
```elixir
# priv/repo/migrations/20251020_create_billing_tables.exs
defmodule Rsolv.Repo.Migrations.CreateBillingTables do
  use Ecto.Migration

  def change do
    create table(:subscriptions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      # ...
    end
  end
end
```

**Include migration safety checklist:**
```bash
mix credo priv/repo/migrations/*.exs
# Check for: no defaults on large tables, concurrent indexes, reversible
```

### 5. Error Handling Pattern (Oban Retry)
**Pattern from RFC-065:**
- **Core operations:** Use Ecto.Multi for atomicity (customer + API key)
- **External services (Stripe, email):** Queue Oban retry jobs if fail
- **Retry limits:** `max_attempts: 3` for workers
- **Fail gracefully:** Core provisioning succeeds even if Stripe/email fails

**Apply to RFC-066:** Stripe API calls should have retry via Oban.

### 6. Transparent Credit Tracking (User Trust)
**Required by RFC-065:**
- Prominent display: "**8/10** free fixes remaining"
- Warning at fix #9: "⚠️ 1 free fix remaining. After that, $15/fix on PAYG."
- **Explicit opt-in** before fix #11: "You've used all 10 free fixes. Continue with PAYG at $15/fix? [Yes] [Pause Scanning]"

**RFC-066 needs backend API** for this:
```elixir
Billing.get_usage_summary(customer)
# Returns: %{plan: "trial", fixes_used: 8, fixes_remaining: 2, ...}
```

### 7. Existing Infrastructure to Reuse
**From RFC-065 analysis:**
- **Rate Limiting:** `Rsolv.RateLimiter` (Mnesia-based, RFC-054, ADR-025)
- **CSRF Protection:** Phoenix built-in `get_csrf_token/0` (lib/rsolv_web.ex)
- **Email Sequence:** `EmailSequence.start_early_access_onboarding_sequence/2`
- **Oban Workers:** `EmailWorker` with `max_attempts: 3` pattern
- **Admin RPC:** `bin/rsolv rpc "Module.function(args)"` pattern

**RFC-066 should reuse these patterns.**

---

## Claude's Review of RFC-066 (Reference Only)

**Date Reviewed:** 2025-10-20
**Current RFC-066 Commit:** `07707673` (includes trial limit note in Quick Start)

### Issues Found

#### 1. Database Schema Uses Raw SQL (Lines 162-181)
**Problem:** Shows `CREATE TABLE` SQL statements instead of Ecto migrations.

**Fix Required:**
```elixir
# priv/repo/migrations/20251020_create_billing_tables.exs
defmodule Rsolv.Repo.Migrations.CreateBillingTables do
  use Ecto.Migration

  def change do
    create table(:subscriptions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :customer_id, references(:customers, on_delete: :delete_all)
      add :stripe_subscription_id, :string
      add :plan, :string
      add :status, :string
      add :current_period_end, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create unique_index(:subscriptions, [:stripe_subscription_id])

    create table(:billing_events, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :customer_id, references(:customers, on_delete: :delete_all)
      add :stripe_event_id, :string
      add :event_type, :string
      add :amount_cents, :integer
      add :metadata, :map

      timestamps(type: :utc_datetime)
    end

    create unique_index(:billing_events, [:stripe_event_id])
  end

  def down do
    drop table(:billing_events)
    drop table(:subscriptions)
  end
end
```

**Add migration safety checklist like RFC-065.**

#### 2. Trial State Machine Oversimplified (Lines 113-123)
**Problem:** Current code doesn't handle 5 vs 10 fix distinction.

```elixir
# Current (too simple):
def track_fix_deployed(customer, fix) do
  case customer.subscription_plan do
    "trial" -> increment_trial_usage(customer)
    "pay_as_you_go" -> charge_customer(customer, 15.00)
    "teams" -> track_teams_usage(customer)
  end
end
```

**Fix Required:**
```elixir
def track_fix_deployed(customer, fix) do
  cond do
    # Trial with fixes remaining
    customer.subscription_plan == "trial" and
    customer.trial_fixes_used < customer.trial_fixes_limit ->
      increment_trial_usage(customer)
      {:ok, :trial_fix_used}

    # Trial expired, block
    customer.subscription_plan == "trial" and
    customer.trial_fixes_used >= customer.trial_fixes_limit ->
      {:error, :trial_expired}

    # PAYG confirmed, charge
    customer.subscription_plan == "pay_as_you_go" and
    customer.payg_confirmed ->
      with {:ok, _} <- Stripe.record_usage(customer, 1),
           {:ok, _} <- charge_customer(customer, 15.00) do
        {:ok, :charged}
      end

    # PAYG not confirmed, require opt-in
    customer.subscription_plan == "pay_as_you_go" and
    not customer.payg_confirmed ->
      {:error, :payg_confirmation_required}

    # Teams plan
    customer.subscription_plan == "teams" ->
      track_teams_usage(customer)
  end
end
```

#### 3. Payment Method Addition Logic Unclear (Lines 125-135)
**Problem:** Function called `convert_to_paid` but should be `add_payment_method`.

**Current flow unclear:**
- When does trial_fixes_limit increment from 5 to 10?
- When do we create Stripe customer?
- When do we create subscription (if ever for PAYG)?

**Fix Required:**
```elixir
# Rename function
def add_payment_method(customer, payment_method_token) do
  with {:ok, stripe_customer} <- Stripe.create_customer(customer),
       {:ok, _} <- Stripe.attach_payment_method(stripe_customer.id, payment_method_token),
       {:ok, updated} <- Customers.update_customer(customer, %{
         stripe_customer_id: stripe_customer.id,
         trial_fixes_limit: 10  # INCREMENT from 5 to 10
       }),
       {:ok, _} <- send_payment_added_email(customer) do
    {:ok, updated}
  else
    {:error, reason} ->
      # Queue Oban retry
      StripeRetryWorker.new(%{
        customer_id: customer.id,
        operation: "create_customer"
      })
      |> Oban.insert()
      {:error, reason}
  end
end
```

**Clarify:** PAYG customers don't get a Stripe subscription. They're charged per-use via `Stripe.UsageRecord`.

#### 4. Explicit PAYG Opt-In Missing
**Problem:** No database field or function for PAYG confirmation.

**Fix Required:**

**Database migration:**
```elixir
alter table(:customers) do
  add :payg_confirmed, :boolean, default: false
  add :payg_confirmed_at, :utc_datetime
end
```

**Function:**
```elixir
def confirm_payg_subscription(customer) do
  customer
  |> Ecto.Changeset.change(%{
    payg_confirmed: true,
    payg_confirmed_at: DateTime.utc_now(),
    subscription_plan: "pay_as_you_go"
  })
  |> Repo.update()
end
```

**UI flow:**
1. Customer uses 10th free fix
2. Next fix attempt blocked with `:trial_expired` error
3. Portal shows: "You've used all 10 free fixes. Continue with PAYG at $15/fix? [Yes] [No]"
4. If Yes → call `confirm_payg_subscription/1`
5. Allow fix #11+ with charging

#### 5. Stripe Customer Creation Timing Ambiguous
**Question:** When do we create Stripe customer?

**Option A:** On signup (all trials)
- Pro: Ready for payment immediately
- Con: Clutters Stripe with non-paying trials

**Option B:** When payment method added (recommended)
- Pro: Only paying customers in Stripe
- Con: Slightly more complex

**Recommendation:** Option B with Oban retry if creation fails.

**Document this explicitly in RFC-066.**

#### 6. Webhook Error Handling Lacks Oban Retry
**Problem:** Webhook handler processes inline, no retry on failure.

**Fix Required:**
```elixir
def stripe(conn, _params) do
  with {:ok, event} <- verify_signature(conn),
       {:ok, _} <- queue_webhook_processing(event) do
    # Acknowledge immediately (Stripe expects 200 within ~30s)
    send_resp(conn, 200, "OK")
  else
    {:error, :invalid_signature} ->
      send_resp(conn, 400, "Invalid signature")
  end
end

defp queue_webhook_processing(event) do
  WebhookProcessorWorker.new(%{
    stripe_event_id: event.id,
    event_type: event.type,
    event_data: event.data
  })
  |> Oban.insert()
end
```

**Worker:**
```elixir
defmodule Rsolv.Workers.WebhookProcessorWorker do
  use Oban.Worker,
    queue: :webhooks,
    max_attempts: 3  # Retry pattern from RFC-065

  @impl Oban.Worker
  def perform(%Oban.Job{args: args}) do
    process_stripe_event(args)
  end
end
```

#### 7. TDD Tasks Need Ecto Migration Clarity (Line 206)
**Problem:** Says "Create billing_events and subscriptions tables" - not clear it's via Ecto.

**Fix Required:**
```markdown
### Week 2: Subscription Management (TDD)
- [ ] **RED**: Write test: "migration creates subscriptions table with correct schema"
- [ ] **RED**: Write test: "migration creates billing_events table with correct schema"
- [ ] **GREEN**: Create Ecto migration `20251020_create_billing_tables.exs`
- [ ] **GREEN**: Run `mix ecto.migrate`
- [ ] **GREEN**: Verify with `mix credo priv/repo/migrations/*.exs`
- [ ] **REFACTOR**: Ensure down/0 function exists
- [ ] Write test: "creates subscription with trial period"
- ...
```

#### 8. Backend API for Transparent Credit Tracking Missing
**Problem:** Portal needs API to display usage stats, but not defined in RFC-066.

**Fix Required:**
```elixir
defmodule Rsolv.Billing do
  @doc """
  Returns usage summary for customer dashboard display.
  Consumed by RFC-071 (Customer Portal UI).
  """
  def get_usage_summary(customer) do
    case customer.subscription_plan do
      "trial" ->
        %{
          plan: "trial",
          fixes_used: customer.trial_fixes_used,
          fixes_limit: customer.trial_fixes_limit,
          fixes_remaining: customer.trial_fixes_limit - customer.trial_fixes_used,
          billing_status: if(customer.stripe_customer_id, do: "payment_added", else: "no_payment"),
          warning: calculate_warning(customer)
        }

      "pay_as_you_go" ->
        usage = get_payg_usage_count(customer, current_billing_period())
        %{
          plan: "pay_as_you_go",
          fixes_this_month: usage,
          amount_this_month: usage * 15.00,
          confirmed: customer.payg_confirmed
        }

      "teams" ->
        usage = get_teams_usage_count(customer, current_billing_period())
        overage = max(0, usage - 60)
        %{
          plan: "teams",
          included_fixes: 60,
          fixes_used: usage,
          overage_fixes: overage,
          overage_amount: overage * 8.00
        }
    end
  end

  defp calculate_warning(customer) do
    remaining = customer.trial_fixes_limit - customer.trial_fixes_used

    cond do
      remaining == 1 -> "⚠️ 1 free fix remaining. After that, $15/fix on PAYG."
      remaining == 0 -> "Trial expired. Continue with PAYG at $15/fix?"
      true -> nil
    end
  end
end
```

**Add TDD tasks for these API functions in Week 3.**

#### 9. Webhook Idempotency Details (Line 204)
**Good:** Test exists for idempotency.

**Clarify implementation:**
```elixir
def process_webhook(event) do
  case Repo.get_by(BillingEvent, stripe_event_id: event.id) do
    nil ->
      # First time seeing this event
      handle_event(event)

      BillingEvent.changeset(%BillingEvent{}, %{
        stripe_event_id: event.id,
        event_type: event.type,
        customer_id: get_customer_id_from_event(event),
        amount_cents: get_amount_from_event(event),
        metadata: event.data
      })
      |> Repo.insert()

    %BillingEvent{} = existing ->
      # Already processed (Stripe sends duplicates)
      Logger.info("Duplicate webhook received", stripe_event_id: event.id)
      {:ok, :duplicate}
  end
end
```

**Unique constraint on `stripe_event_id` prevents race conditions.**

#### 10. Integration Flow with RFC-065 Missing
**Problem:** How do provisioning and billing connect?

**Document explicitly:**

```markdown
## Integration with RFC-065 Provisioning

### Signup (RFC-065)
1. Customer submits email/name via form
2. `Provisioning.provision_customer/1` called
3. Customer created: `subscription_plan: "trial"`, `trial_fixes_limit: 5`
4. API key generated and emailed
5. **NO Stripe customer created yet**

### Add Payment Method (RFC-066)
1. Customer visits dashboard, clicks "Add Payment"
2. Stripe Checkout collects payment method
3. `Billing.add_payment_method/2` called with token
4. **Create Stripe customer** (with Oban retry if fails)
5. Attach payment method
6. **Increment trial_fixes_limit to 10** (from 5)
7. Email: "You now have 10 total free fixes!"

### Trial Expiration (RFC-066)
1. Customer uses 10th free fix
2. Next fix attempt: `track_fix_deployed/2` returns `{:error, :trial_expired}`
3. Portal shows opt-in prompt: "Continue with PAYG at $15/fix?"
4. If confirmed: `confirm_payg_subscription/1` sets `payg_confirmed: true`
5. Allow fix #11+ with charging

### Fix Deployment (RFC-066 + RFC-060)
1. RSOLV Action completes VALIDATE/MITIGATE phases
2. PhaseDataClient reports success
3. `Billing.track_fix_deployed/2` called
4. If PAYG: Create Stripe UsageRecord, charge $15
5. If Teams: Increment usage counter, check overage
```

#### 11. Success Metrics Without Customers (Lines 257-260)
**Problem:** Says "Payment Success: > 95%" but no customers yet.

**Fix:** Add note like RFC-065:
```markdown
**Note:** These are target metrics. Actual measurement begins post-launch
with beta customers (Week 5-6 of RFC-064).
```

#### 12. "Teams" Clarification
**Good:** Already shows Teams as pricing tier.

**Suggest adding:**
```markdown
**Note:** "Teams" is a pricing tier (volume discount), not a multi-user feature.
Single-user accounts can subscribe to Teams plan for $8.32/fix vs $15/fix PAYG.
```

---

## Q&A Summary (All 13 Clarifications)

### 1. Post-Early Access World
**Decision:** Unify now (Option B). Replace early access flow with production customer signup.

### 2. Trial Limits
**Decision:** 5 on signup, +5 when billing added (total 10), then PAYG with explicit opt-in.

### 3. Conversion Model
**Decision:** Immediate to PAYG. Adding payment = ready to pay, with transparent credit tracking.

### 4. Programmatic API
**Decision:** API-first module callable from REST endpoint, web form, admin RPC.

### 5. GitHub Marketplace Workflow Install
**Decision:** Keep manual copy/paste for now. GitHub App is RFC-076 (future).

### 6. Email Validation
**Decision:** Disposable domain blocking (`burnex` lib). GitHub OAuth deferred to RFC-072.

### 7. Setup Wizard
**Decision:** Show until first scan completes. Manual dismiss/re-enter controls.

### 8. Error Handling
**Decision:** Partial success + Oban retry (Option B). Core operations atomic, external services retried.

### 9. Load Testing
**Decision:** Tests + config + success criteria. All three covered.

### 10. API Key Hashing
**Decision:** SHA256 (not Bcrypt/Argon2). Phoenix best practice for random tokens.

### 11. Admin Overrides
**Decision:** RPC-compatible module. Production-safe, no mix tasks in releases.

### 12. Email Retry
**Decision:** Postmark + Oban (3 attempts). Fallback providers later if needed.

### 13. Future Enhancements
**Decision:** Track as new RFCs (072, 074, 075, 076). 073 removed.

---

## Files Changed This Session

### Modified:
- `RFCs/RFC-065-AUTOMATED-CUSTOMER-PROVISIONING.md` (comprehensive revision)
- `RFCs/RFC-066-STRIPE-BILLING-INTEGRATION.md` (trial limit note added)
- `RFCs/RFC-068-BILLING-TESTING-INFRASTRUCTURE.md` (test scenarios updated)
- `RFCs/RFC-INDEX.md` (RFC-072 through RFC-076 added, RFC-073 marked removed)

### Created:
- `RFCs/RFC-070-CUSTOMER-AUTHENTICATION.md` (skeleton)
- `RFCs/RFC-071-CUSTOMER-PORTAL-UI.md` (skeleton)
- `RFCs/RFC-072-OAUTH-INTEGRATION.md` (skeleton)
- `RFCs/RFC-074-CLI-PROVISIONING.md` (skeleton)
- `RFCs/RFC-075-SIGNUP-WEBHOOKS.md` (skeleton)
- `RFCs/RFC-076-GITHUB-APP-WORKFLOW-INSTALL.md` (skeleton)

### Removed:
- `RFCs/RFC-073-MULTI-USER-ACCOUNTS.md` (conflated pricing with features)

---

## Next Session Tasks

1. **Dylan provides his review notes on current RFC-066**
2. **Review both sets of notes** (Dylan's + Claude's above)
3. **Identify conflicts/agreements** between reviews
4. **Revise RFC-066** addressing both reviews
5. **Update related docs** if needed (RFC-INDEX, etc.)
6. **Commit and push** changes

---

## Key Reminders for Next Session

### Critical Rules
- **Ecto migrations only** - No raw SQL anywhere
- **API-first design** - Self-contained modules, no web dependencies
- **Oban retry pattern** - External services (Stripe, email) retry via Oban
- **Trial model** - 5 → 10 → PAYG with explicit opt-in
- **"Teams" = pricing** - Not multi-user features

### Context to Carry Forward
- RFC-065 establishes patterns for RFC-066 to follow
- All infrastructure to reuse already identified
- Integration touchpoints documented
- Future RFCs (072, 074, 075, 076) waiting for RFC-064 completion

### Don't Forget
- Migration safety checklist
- TDD tasks with RED-GREEN-REFACTOR
- OpenAPI specs (if API endpoints added)
- Cross-reference existing implementations

---

## Git Commit References

- `6d2a6489` - RFC-065 comprehensive revision + RFC-066/068 updates
- `b7c82a05` - RFC-070 through RFC-076 skeletons + index
- `07707673` - Removed RFC-073 (multi-user/pricing conflation)

**Current Branch:** `main`
**All changes pushed:** ✅

---

End of Context Handoff Document
