# Stripe Webhook Testing Checklist

**Task**: Verify all 5 critical Stripe webhook events work correctly
**Estimated Time**: 2-3 hours
**Implementation**: PR #31 (merged)

## Quick Start

```bash
# 1. Setup test customer (using Ecto)
mix run --no-start test/scripts/setup_webhook_test_customer.exs
# ⚠️  SAVE the stripe_customer_id from output!

# 2. Start Phoenix (Terminal 1)
mix phx.server

# 3. Start Stripe CLI forwarding (Terminal 2)
stripe listen --forward-to http://localhost:4000/api/webhooks/stripe
# ⚠️  COPY the webhook secret (whsec_...) and:
export STRIPE_WEBHOOK_SECRET=whsec_xxxxxxxxxxxxxxxxxxxxx
# Then RESTART Phoenix server

# 4. Verify setup works (Terminal 3)
test/scripts/verify_webhooks.sh
```

## Test Execution

Replace `cus_test_XXXX` with your actual customer ID.

### ☐ Test 1: invoice.payment_succeeded

```bash
stripe trigger invoice.payment_succeeded --override customer=cus_test_XXXX
test/scripts/verify_webhooks.sh
```

**Expected**:
- ✅ +60 credits added to customer balance
- ✅ Billing event recorded
- ✅ Oban job completed
- ✅ Log: "Pro subscription payment processed...credits_added=60"

**Verification Query**:
```sql
SELECT credit_balance FROM customers WHERE email = 'webhook-test@example.com';
-- Should show +60 from starting balance
```

---

### ☐ Test 2: invoice.payment_failed

```bash
stripe trigger invoice.payment_failed --override customer=cus_test_XXXX
test/scripts/verify_webhooks.sh
```

**Expected**:
- ✅ subscription_state set to 'past_due'
- ✅ Billing event recorded
- ✅ Log: "Payment failed for customer..."

**Verification Query**:
```sql
SELECT subscription_state FROM customers WHERE email = 'webhook-test@example.com';
-- Should be 'past_due'
```

---

### ☐ Test 3: customer.subscription.created

```bash
stripe trigger customer.subscription.created --override customer=cus_test_XXXX
test/scripts/verify_webhooks.sh
```

**Expected**:
- ✅ stripe_subscription_id populated (sub_xxxxx)
- ✅ subscription_type set to 'pro'
- ✅ subscription_state set to 'active' or 'trialing'
- ✅ Log: "Subscription created...stripe_subscription_id=sub_xxxxx"

**Verification Query**:
```sql
SELECT stripe_subscription_id, subscription_type, subscription_state
FROM customers WHERE email = 'webhook-test@example.com';
-- stripe_subscription_id should be set, type='pro', state='active'/'trialing'
```

---

### ☐ Test 4: customer.subscription.deleted

```bash
# Note current credit_balance first!
stripe trigger customer.subscription.deleted --override customer=cus_test_XXXX
test/scripts/verify_webhooks.sh
```

**Expected**:
- ✅ subscription_type changed to 'pay_as_you_go'
- ✅ subscription_state cleared (NULL)
- ✅ stripe_subscription_id cleared (NULL)
- ✅ subscription_cancel_at_period_end set to false
- ✅ **credit_balance PRESERVED** (not reset!)
- ✅ Log: "Subscription canceled, downgraded to PAYG...credits_remaining=X"

**Verification Query**:
```sql
SELECT subscription_type, subscription_state, stripe_subscription_id,
       credit_balance, subscription_cancel_at_period_end
FROM customers WHERE email = 'webhook-test@example.com';
-- type='pay_as_you_go', state=NULL, sub_id=NULL, credits=UNCHANGED
```

---

### ☐ Test 5: customer.subscription.updated

```bash
stripe trigger customer.subscription.updated \
  --override customer=cus_test_XXXX \
  --override cancel_at_period_end=true
test/scripts/verify_webhooks.sh
```

**Expected**:
- ✅ subscription_cancel_at_period_end set to true
- ✅ subscription_state updated
- ✅ Log: "Subscription scheduled for cancellation at period end..."

**Verification Query**:
```sql
SELECT subscription_state, subscription_cancel_at_period_end
FROM customers WHERE email = 'webhook-test@example.com';
-- cancel_at_period_end should be true
```

---

### ☐ Test 6: Idempotency

```bash
# Method 1: Re-trigger the same event type (generates NEW event ID)
stripe trigger invoice.payment_succeeded --override customer=cus_test_XXXX

# Method 2: Check for duplicate processing (should be NONE)
psql $DATABASE_URL -c "
SELECT stripe_event_id, COUNT(*) as count
FROM billing_events
GROUP BY stripe_event_id
HAVING COUNT(*) > 1;
"
```

**Expected**:
- ✅ Each unique event ID processed exactly once
- ✅ Re-triggering creates new event (not a duplicate)
- ✅ No duplicate stripe_event_id in billing_events table
- ✅ Log for true duplicate: "Duplicate webhook received stripe_event_id=evt_xxxxx"

**Note**: Stripe CLI generates unique event IDs, so re-running triggers won't test idempotency. True idempotency test requires manually replaying the same event ID (see detailed guide).

---

## System Checks

### ☐ All webhooks return 200 to Stripe CLI

Check Terminal 2 (Stripe CLI) output - should show:
```
--> invoice.payment_succeeded [evt_xxxxx]
<-- [200] POST http://localhost:4000/api/webhooks/stripe [evt_xxxxx]
```

All events should have `[200]` response.

---

### ☐ No processing errors in Phoenix logs

Check Terminal 1 for:
- ❌ No `[error]` lines related to webhook processing
- ✅ All logs show `[info]` with "processed successfully"
- ✅ No database constraint violations
- ✅ No Ecto errors

---

### ☐ All Oban jobs completed successfully

```sql
SELECT state, COUNT(*)
FROM oban_jobs
WHERE queue = 'webhooks'
GROUP BY state;
```

**Expected**:
- ✅ All jobs in state 'completed'
- ❌ No jobs in state 'discarded' or 'retryable'

---

### ☐ No duplicate events in database

```sql
SELECT stripe_event_id, COUNT(*) as occurrences
FROM billing_events
GROUP BY stripe_event_id
HAVING COUNT(*) > 1;
```

**Expected**: Empty result (no duplicates)

---

### ☐ Credit balance increased correctly

Starting balance: `0`

After payment_succeeded: `0 + 60 = 60`

After subscription_deleted: `60` (preserved!)

```sql
SELECT credit_balance FROM customers WHERE email = 'webhook-test@example.com';
```

---

## Success Criteria

All tests pass when you can check ALL of these:

- [x] ✅ invoice.payment_succeeded adds 60 credits
- [x] ✅ invoice.payment_failed sets subscription_state to 'past_due'
- [x] ✅ subscription.created records subscription ID and sets type to 'pro'
- [x] ✅ subscription.deleted downgrades to PAYG and preserves credits
- [x] ✅ subscription.updated sets cancel_at_period_end flag
- [x] ✅ No duplicate billing_events (unique stripe_event_id constraint works)
- [x] ✅ All Oban jobs completed successfully
- [x] ✅ All webhooks returned 200 to Stripe
- [x] ✅ No errors in Phoenix logs
- [x] ✅ Database state matches expected values

## Quick Verification

After running all tests, this command should show no issues:

```bash
test/scripts/verify_webhooks.sh
```

Look for:
- ✅ Test customer exists
- ✅ 5+ billing events recorded (one per test)
- ✅ No failed webhook jobs
- ✅ No duplicate events

## Troubleshooting

### No webhooks received?
1. Check Phoenix is running on port 4000
2. Check Stripe CLI shows "Ready! You are using Stripe API Version..."
3. Verify `--forward-to http://localhost:4000/api/webhooks/stripe`

### Signature verification failed?
1. Copy the webhook secret from Terminal 2
2. Run: `export STRIPE_WEBHOOK_SECRET=whsec_...`
3. Restart Phoenix server

### Customer not found?
1. Check customer exists: `psql $DATABASE_URL -c "SELECT * FROM customers WHERE email = 'webhook-test@example.com';"`
2. Verify stripe_customer_id matches trigger command
3. Re-run: `mix run --no-start test/scripts/setup_webhook_test_customer.exs`

### Jobs failing?
1. Check Oban dashboard: http://localhost:4000/dev/dashboard
2. View failed job details in `oban_jobs` table
3. Check worker logs for error details

## Cleanup

```sql
-- Delete test data
DELETE FROM billing_events
WHERE customer_id = (SELECT id FROM customers WHERE email = 'webhook-test@example.com');

DELETE FROM credit_transactions
WHERE customer_id = (SELECT id FROM customers WHERE email = 'webhook-test@example.com');

DELETE FROM customers WHERE email = 'webhook-test@example.com';
```

## Time Tracking

- [ ] Setup (30 min)
- [ ] Test execution (60 min)
- [ ] Verification & debugging (30 min)
- [ ] Documentation (30 min)

**Total**: 2-3 hours

## Related Files

- Full guide: `docs/STRIPE-WEBHOOK-TESTING.md`
- Setup script: `test/scripts/setup_webhook_test_customer.exs`
- Verify script: `test/scripts/verify_webhooks.sh`
- Implementation: `lib/rsolv/billing/webhook_processor.ex`
- Worker: `lib/rsolv/workers/stripe_webhook_worker.ex`
- Controller: `lib/rsolv_web/controllers/webhook_controller.ex`

## References

- RFC-065: Billing Core
- RFC-066: Billing Integration
- PR #31: Webhook Implementation
- Stripe Webhooks: https://stripe.com/docs/webhooks
- Stripe CLI: https://stripe.com/docs/stripe-cli
