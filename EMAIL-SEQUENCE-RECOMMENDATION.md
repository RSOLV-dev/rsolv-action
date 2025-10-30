# Email Sequence Recommendation: Early Access vs Conventional Signup

**Date**: 2025-10-30
**Context**: RFC-065 Polish - Deciding email drip campaign strategy
**Status**: Recommendation Ready for Decision

## Current Situation

We have TWO email sequences:

### 1. Early Access Onboarding (`early_access_onboarding`)
- **Day 0**: Early Access Welcome (says "API key coming in 24 hours")
- **Day 1**: Early Access Guide (template exists but not wired up)
- **Day 3**: Setup Verification
- **Day 5**: Feature Deep Dive
- **Day 7**: Feedback Request
- **Day 14**: Success Check-in

### 2. Conventional Onboarding (`onboarding`)
- **Day 0**: Welcome (says "Here's your API key, get started")
- **Day 1**: Getting Started
- **Day 2**: Setup Verification
- **Day 3**: First Issue
- **Day 5**: Feature Deep Dive
- **Day 7**: Feedback Request
- **Day 14**: Success Check-in

## Current Implementation Status

| Component | Early Access | Conventional | Status |
|-----------|--------------|--------------|--------|
| Welcome email template | ✅ | ✅ | Both implemented |
| Day 1 email template | ✅ (early_access_guide) | ✅ (getting_started) | Both implemented in Emails module |
| Day 1 EmailService function | ❌ Missing | ✅ | **Early access guide needs wiring** |
| Day 1 EmailWorker handler | ❌ Placeholder error | ✅ | **Early access guide not wired** |
| CustomerOnboarding calls | `early_access_onboarding` | N/A | Currently using early access |

## Key Differences

### Early Access Welcome Email Content
```
"Your API key will be sent in a follow-up email within 24 hours"
"Look for an email with subject 'Your RSOLV API Key'"
"Unlimited usage during Early Access"
"Exclusive pricing when we launch"
```

### Conventional Welcome Email Content
```
"Here's your API key" (immediately shown)
"Your first 10 fixes are free!"
"After that, you only pay $15 per fix"
```

### Early Access Guide (Day 1) vs Getting Started (Day 1)

**Early Access Guide**:
- Emphasizes security-first approach
- Explains "how to write effective issues"
- Says "Early Access Note: As an early access user, you may occasionally encounter limitations"
- Focuses on early access program benefits

**Getting Started**:
- Quick feature overview
- Simpler, more polished
- No mention of limitations
- Success-based billing prominently featured

## Business Context

**You said**:
> "We're out of our initial early access phase. (We'll do another early access.)"

This means:
- Current signups should be **conventional** (not early access)
- We're in production launch mode
- Next early access will be for future features/betas

## Recommendation: **Transition to Conventional Sequence**

### Why Conventional is Better Now

1. **API Key Delivery**: We now provision API keys immediately via automated onboarding (RFC-065). The early access email saying "API key coming in 24 hours" is wrong and confusing.

2. **Messaging Accuracy**: Early access language like "you may encounter limitations" and "exclusive pricing when we launch" is outdated. We've launched.

3. **Pricing Clarity**: Conventional sequence correctly communicates:
   - 5 credits on signup
   - +5 more when adding billing (total 10)
   - Then $29/fix PAYG or Pro plan

4. **Better Day 1 Content**: "Getting Started" is more polished and actionable than "Early Access Guide"

5. **Future Flexibility**: Keep early access sequence for next beta/early access program

### Implementation Plan

**Option A: Switch Everyone to Conventional** (RECOMMENDED)

Changes needed:
1. Update `CustomerOnboarding.start_early_access_onboarding_sequence` to `start_onboarding_sequence`
2. No other code changes needed - conventional sequence is fully implemented

```elixir
# lib/rsolv/customer_onboarding.ex:149
# BEFORE:
EmailSequence.start_early_access_onboarding_sequence(customer.email, customer.name)

# AFTER:
EmailSequence.start_onboarding_sequence(customer.email, customer.name)
```

**Files to change**: 1 file, 1 line

**Option B: Fix Early Access Guide Handler**

Changes needed:
1. Add `send_early_access_guide_email/2` to EmailService
2. Update EmailWorker to call it instead of returning error

```elixir
# lib/rsolv/email_service.ex (add after line 96)
def send_early_access_guide_email(email, first_name \\ nil) do
  email
  |> Emails.early_access_guide_email(first_name)
  |> send_email()
end

# lib/rsolv/workers/email_worker.ex:67-69 (replace)
"early_access_guide" ->
  EmailService.send_early_access_guide_email(email, first_name)
```

**Files to change**: 2 files, ~15 lines

**Option C: Hybrid Approach**

- Use conventional sequence for normal signups
- Keep early access sequence for when we run next beta
- Add feature flag to toggle between them

**Complexity**: Medium (requires feature flag logic)

## Comparison Matrix

| Criterion | Option A (Switch to Conventional) | Option B (Fix Early Access) | Option C (Hybrid) |
|-----------|-----------------------------------|----------------------------|-------------------|
| **Effort** | Minimal (1 line) | Low (2 files) | Medium (feature flags) |
| **Accuracy** | High - matches current business model | Medium - perpetuates outdated messaging | High - flexible |
| **Risk** | Very Low | Medium - keeps confusing messaging | Low |
| **Maintenance** | Low - one sequence to maintain | High - two sequences | Medium - need flag management |
| **Future Flexibility** | Medium - can switch back for next EA | Medium - already have EA ready | High - toggle anytime |
| **Message Accuracy** | ✅ API key shown immediately | ❌ "Coming in 24 hours" (wrong) | ✅ Can customize per program |
| **Pricing Communication** | ✅ Clear 5+5 credits, then PAYG | ⚠️ "Unlimited during EA" (outdated) | ✅ Can customize |

## My Recommendation: **Option A - Switch to Conventional**

### Rationale

1. **Immediate API Key**: RFC-065 automated provisioning means customers get API keys instantly. Early access email saying "coming in 24 hours" is confusing and inaccurate.

2. **Post-Launch Reality**: We're past beta. Messaging should reflect production status, not early access.

3. **Less Confusion**: Conventional sequence has accurate pricing, no mention of limitations, clearer onboarding.

4. **Minimal Work**: Literally one line change.

5. **Reversible**: When running next early access program, switch back with one line.

6. **Better Tested**: Conventional sequence is fully implemented and tested. Early access guide has placeholder error.

### When to Use Each Sequence Going Forward

**Conventional (`onboarding`)**:
- Regular signups via /signup
- GitHub Marketplace installs
- Self-service customers
- Current default

**Early Access (`early_access_onboarding`)**:
- Next time we run a beta/early access program
- New feature previews
- Invitation-only programs
- Explicit opt-in to early access

## Implementation Steps (Option A)

### 1. Update CustomerOnboarding (1 line change)

```bash
# File: lib/rsolv/customer_onboarding.ex
# Line: 155
```

```elixir
# BEFORE:
{:ok, _result} =
  EmailSequence.start_early_access_onboarding_sequence(customer.email, customer.name)

# AFTER:
{:ok, _result} =
  EmailSequence.start_onboarding_sequence(customer.email, customer.name)
```

### 2. Update Tests

The test at `test/rsolv/customer_onboarding_test.exs:78` checks for `send_early_access_welcome_email` in logs. Update to check for `send_welcome_email` instead.

```elixir
# test/rsolv/customer_onboarding_test.exs:78
# BEFORE:
assert log =~ "send_early_access_welcome_email"

# AFTER:
assert log =~ "send_welcome_email"
```

And line 99:
```elixir
# BEFORE:
assert log =~ "Starting early_access_onboarding sequence"

# AFTER:
assert log =~ "Starting onboarding sequence"
```

### 3. Run Tests

```bash
mix test test/rsolv/customer_onboarding_test.exs
```

### 4. Update Documentation

Update `projects/rfc-065-onboarding-2025-10/WEEK-3-EMAIL-SEQUENCE-STATUS.md` to reflect:
- Now using conventional sequence
- Early access sequence available for future use
- Day 1 email issue resolved (using getting_started)

## Alternative: If You Want to Keep Early Access

If there's a business reason to keep using early access messaging (e.g., soft launch, invite-only still), then:

**Option B is better**: Fix the early access guide wiring (15 lines of code)

**But you must also**:
1. Update early access welcome email template to say API key is included in THIS email (not 24 hours)
2. Remove "unlimited usage" messaging (not accurate with credit system)
3. Remove "exclusive pricing when we launch" (we've launched)
4. Update to reflect actual pricing (5 credits → 10 with billing → PAYG)

This requires more extensive template updates across multiple files.

## Decision Needed

**Question**: Should new signups get:
- A) Conventional onboarding (production messaging, API key immediate, accurate pricing)
- B) Early access onboarding (beta messaging, needs template fixes)

**My vote**: A - Conventional onboarding

**Reason**: We're post-launch, API keys are immediate, pricing is clear. Save early access sequence for next beta program.

---

## Next Steps After Decision

Once you decide, I'll:
1. Make the code changes (1-15 lines depending on choice)
2. Update tests
3. Verify email flow
4. Update documentation
5. Create summary for merge
