# Skipped Tests Analysis & Recommendations

**Date**: 2025-10-29 (Updated after Week 3 test fixes)
**Current Coverage**: 59.02% (expected to increase after fixes)
**Target Coverage**: 70%
**Total Skipped**: 60 tests (down from 65)
**Total Excluded**: 83 tests (integration tag)
**Total Passing**: 4,518 tests (up from 4,504)
**Total Failing**: 4 tests (down from 19)

## Executive Summary

We have **60 skipped tests** and **83 excluded integration tests** (143 total not running). Recent Week 3 work fixed **14 failing tests** and unskipped **5 tests** (4 billing + 1 rate limiting).

**Recent Progress (2025-10-29)**:
- ✅ Fixed 14 tests (3 billing mocks, 1 webhook signature, 8+ webhook processor, 2 other)
- ✅ Unskipped 4 billing tests (implemented Stripe mocking)
- ✅ Unskipped 1 rate limiting test
- ⚠️ 4 tests still failing (requires implementation work, not just fixes)

**Key Findings**:
1. **9 consolidation tests** - Phase 2 schema work (future implementation)
2. **0 billing tests** - ✅ All billing tests now passing with Mox
3. **5 security tests** - PCI compliance and SQL injection (can likely implement)
4. **3 feature tests** - Implementation not complete (Java parsing, dark mode)
5. **3 unimplemented functions** - Need implementation before unskipping

## Current Failing Tests (4 tests - Requires Implementation)

### 1. AST Comment Detection (1 test)

**File**: `test/integration/ast_validation_comprehensive_test.exs`
**Test**: Line 61 - detects multi-line JavaScript comments

**Issue**: The AST-based validator is not detecting that vulnerability code is inside a comment, so it returns `isValid: true` when it should return `isValid: false, reason: "code is in a comment"`.

**Test Expectation**:
```javascript
/* eval(userInput) */  // Should be rejected as false positive
```

**Current Behavior**: Returns `isValid: true` (vulnerability detected)
**Expected Behavior**: Returns `isValid: false, confidence: <0.1, reason: "code is in a comment"`

**Recommendation**: ⚠️ **Requires AST Enhancement**
**Reason**: Need to implement comment node detection in the AST analysis engine.

**Action Required**:
1. Enhance AST analysis to detect comment nodes
2. Add comment filtering logic to validation
3. Update confidence scoring for commented code
4. Unskip test after implementation

**Estimated Impact**: 0% coverage (test already exists, just failing)

---

### 2. Customer Onboarding Events Ordering (1 test)

**File**: `test/rsolv/customer_onboarding/events_test.exs`
**Test**: Line 221 - creates complete audit trail for customer provisioning flow

**Issue**: Test expects events ordered by `inserted_at DESC` (newest first), but assertion fails with oldest event returned first.

**Test Pattern**:
```elixir
# Creates 3 events with 50ms sleeps:
log_customer_created(customer)     # Event 1
Process.sleep(50)
log_api_key_generated(customer)    # Event 2
Process.sleep(50)
log_email_sent(customer)           # Event 3

# Expects: [email_sent, api_key_generated, customer_created]
# Gets: [customer_created, ...]  # Wrong!
```

**Current Behavior**: `Enum.at(events, 0).event_type == "customer_created"` (oldest first)
**Expected Behavior**: `Enum.at(events, 0).event_type in ["email_sent", "api_key_generated"]` (newest first)

**Recommendation**: ⚠️ **Test Isolation Issue**
**Reason**: Query has correct `ORDER BY c0."inserted_at" DESC, c0."id" DESC` but test may have data pollution from other tests. Test uses `async: false` and `DataCase` which should provide isolation.

**Action Required**:
1. Debug why events are returned in wrong order
2. Check if database transactions are being committed properly
3. Verify test cleanup between test runs
4. May need to add explicit cleanup in test setup

**Estimated Impact**: 0% coverage (test already exists, just failing)

---

### 3. Rate Limiting Headers (2 tests)

**File**: `test/security/rate_limiting_test.exs`

**Tests**:
- Line 42: includes rate limit headers
- Line 64: allows failed login attempts up to limit

**Issue**: API responses are missing rate limit headers:
- `x-ratelimit-limit` (e.g., "500")
- `x-ratelimit-remaining` (e.g., "499")
- `x-ratelimit-reset` (Unix timestamp)

**Current Behavior**: Headers not present in response
**Expected Behavior**: All API responses include rate limit headers

**Recommendation**: ⚠️ **Requires Implementation**
**Reason**: Rate limiting logic exists (using Mnesia), but headers aren't being added to responses.

**Action Required**:
1. Update rate limiter plug to add headers to `conn`
2. Include current usage, limit, and reset time in headers
3. Add headers for all API responses (not just when rate limited)
4. Unskip tests after implementation

**Estimated Impact**: 0% coverage (rate limiter already implemented, just missing headers)

---

## Categorized Skipped Tests

### 1. Consolidation/Phase 2 Schema Tests (9 tests)

**File**: `test/consolidation/phase2_schema_test.exs`

These are placeholder tests for future Phase 2 work. They test schema changes that haven't been implemented yet.

**Tests**:
- users table exists with auth fields
- customers table references users table
- api_keys table for multiple keys per customer
- feature_flags table exists for FunWithFlags
- feature flags can be scoped to customers
- email_subscriptions table for marketing emails
- email subscriptions can be linked to users
- fix_attempts table tracks usage
- customers have usage limits and tracking

**Recommendation**: ❌ **Keep Skipped**
**Reason**: These represent future work (Phase 2 schema consolidation). Not ready for implementation.

**Action**: None - leave as placeholder tests

---

### 2. Billing/Stripe Integration Tests (4 tests) - ✅ COMPLETED

**File**: `test/rsolv/billing/fix_deployment_test.exs`

**Status**: ✅ **All 4 tests now passing** (unskipped 2025-10-29)

**Tests** (all passing):
- Line 68: charges PAYG rate ($29) when out of credits ✅
- Line 96: charges discounted rate ($15) for Pro additional ✅
- Line 124: credits then consumes after charge ✅
- Line 144: handles Stripe payment failure gracefully ✅

**Implementation**: Used Mox library to mock `Rsolv.Billing.StripeChargeMock.create/1`

**Related Fixes**:
- Fixed 3 tests in `test/rsolv/billing_test.exs` (changed from `StripeMock` to `StripeChargeMock`)
- Fixed `CreditLedger.credit/4` API call in webhook processor (was using keyword syntax instead of positional)

**Impact**: These tests now contribute to coverage of billing charge logic.

---

### 3. Security/Compliance Tests (5 tests)

#### PCI Compliance (4 tests)

**File**: `test/security/pci_compliance_test.exs`

**Tests**:
- Line 68: no card numbers stored in database
- Line 82: no CVV codes stored in database
- Line 88: only Stripe IDs stored for payment methods
- Line 139: database connections use SSL

**Recommendation**: ✅ **Can Be Unskipped**
**Reason**: These are assertion-based tests that verify our schema and configuration. They don't require new implementation - just proper test setup.

**Action Required**:
1. Query `customers` table schema to verify no card_number/cvv columns
2. Verify only `stripe_customer_id` and `stripe_subscription_id` fields exist
3. Check database connection config for SSL settings
4. Write assertions based on actual schema

**Estimated Impact**: 0% (these test configuration, not new code)

#### SQL Injection Test (1 test)

**File**: `test/security/sql_injection_test.exs`

**Test**:
- Line 55: full-text search sanitizes input

**Recommendation**: ⚠️ **Implement Then Unskip**
**Reason**: We don't currently have full-text search. If we implement it, this test should be unskipped.

**Action**: Keep skipped until full-text search is implemented.

---

### 4. Java Parsing Tests (2 tests)

**File**: `test/rsolv/ast/multi_language_parsing_test.exs`

**Tests**:
- Line 156: parses simple Java code
- Line 167: detects Java command injection

**Recommendation**: ⚠️ **Blocked by Parser Implementation**
**Reason**: Our AST parser doesn't support Java yet. The parser registry only supports JavaScript currently.

**Action Required**:
1. Implement Java parser integration (tree-sitter-java)
2. Add Java patterns to pattern system
3. Test Java AST parsing
4. Unskip these tests

**Estimated Impact**: 1-2% coverage (new Java parsing code)

---

### 5. Rate Limiting Test (1 test) - ✅ COMPLETED

**File**: `test/rsolv_web/controllers/api/v1/ast_controller_test.exs`

**Status**: ✅ **Test now passing** (unskipped 2025-10-29)

**Test**:
- Line 329: enforces rate limiting ✅

**Implementation**: Updated test to use Mnesia-based rate limiter with proper setup.

**Note**: 2 other rate limiting tests in `test/security/rate_limiting_test.exs` are still failing because they expect rate limit headers to be included in responses, which requires additional implementation work (see "Current Failing Tests" section above).

**Estimated Impact**: 0% (rate limiter already implemented, test was just skipped)

---

### 6. Unimplemented Function Tests (3 tests)

#### API Key Revocation

**File**: `test/rsolv/accounts_test.exs`

**Test**:
- Line 47: returns nil for revoked API key

**Comment**: "revoke_api_key function not implemented yet"

**Recommendation**: ⚠️ **Implement Then Unskip**
**Reason**: Feature not built yet.

**Action**: Implement `revoke_api_key/1` function, then unskip.

#### Usage Metrics Recording

**File**: `test/rsolv_web/controllers/credential_controller_test.exs`

**Test**:
- Line 392: records usage metrics

**Comment**: "get_customer_usage function not implemented yet"

**Recommendation**: ⚠️ **Implement Then Unskip**
**Reason**: Feature not built yet.

**Action**: Implement `get_customer_usage/1` function, then unskip.

#### Dark Mode CSS

**File**: `test/rsolv_web/features/dark_mode_test.exs`

**Test**:
- Line 67: dark mode CSS variables are defined in compiled CSS

**Recommendation**: ✅ **Can Be Unskipped**
**Reason**: Dark mode WAS implemented. This test just needs to verify the compiled CSS.

**Action Required**:
1. Compile CSS assets
2. Read compiled CSS file
3. Assert dark mode variables exist
4. Unskip test

**Estimated Impact**: 0% (CSS compilation already happens)

---

## Integration Tests (83 excluded)

**File**: `test/rsolv/ast/parser_registry_test.exs` (2 tests tagged `:integration`)

**Total Excluded**: 83 tests
**Located**: Only 2 found with explicit `:integration` tag

**Mystery**: Where are the other 81 excluded tests?

**Action Required**: Investigate test configuration to find where 81 tests are being excluded.

Possible locations:
- `test/test_helper.exs` might be excluding based on other criteria
- Tests might have multiple tags that cause exclusion
- Some tests might be in directories that are excluded

---

## Quick Wins for Coverage Improvement

### Completed Quick Wins (5 tests, ~0-1% coverage) ✅

1. **✅ Billing Tests with Stripe Mocking** (4 tests) - COMPLETED 2025-10-29
   - Used Mox library to mock Stripe API
   - All 4 tests now passing
   - Coverage of billing charge logic improved

2. **✅ Rate Limiting Test** (1 test) - COMPLETED 2025-10-29
   - Fixed test setup with Mnesia rate limiter
   - Test now passing
   - No new coverage (already implemented)

### Remaining Immediate Unskip Candidates (5 tests, ~0% coverage)

1. **PCI Compliance Tests** (4 tests) - `test/security/pci_compliance_test.exs`
   - Just need schema assertions
   - Zero implementation required

2. **Dark Mode CSS Test** (1 test) - `test/rsolv_web/features/dark_mode_test.exs`
   - Read compiled CSS file
   - Assert variables exist

### Medium-Term Implementation (3 tests, ~0% coverage)

1. **API Key Revocation** - Implement `revoke_api_key/1`
2. **Usage Metrics** - Implement `get_customer_usage/1`
3. **SQL Injection Test** - Only if we implement full-text search

### Long-Term Work (11 tests, ~2-3% coverage)

1. **Phase 2 Consolidation** (9 tests) - Future schema work
2. **Java Parsing** (2 tests) - Requires parser implementation

---

## Recommendations Summary

| Category | Tests | Status | Action | Coverage Impact | Priority |
|----------|-------|--------|--------|-----------------|----------|
| Billing/Stripe | 4 | ✅ DONE | Unskipped 2025-10-29 | ~1% | ~~High~~ |
| Rate Limiting (AST) | 1 | ✅ DONE | Unskipped 2025-10-29 | 0% | ~~High~~ |
| PCI Compliance | 4 | PENDING | Unskip + write assertions | 0% | High |
| Dark Mode CSS | 1 | PENDING | Unskip + read compiled file | 0% | High |
| Failing: AST Comments | 1 | FAILING | Implement comment detection | 0% | High |
| Failing: Event Ordering | 1 | FAILING | Debug test isolation | 0% | Medium |
| Failing: Rate Limit Headers | 2 | FAILING | Implement response headers | 0% | Medium |
| Unimplemented Functions | 3 | PENDING | Implement then unskip | 0-1% | Medium |
| Java Parsing | 2 | PENDING | Implement parser | 1-2% | Low |
| Phase 2 Schema | 9 | SKIPPED | Keep skipped (future) | N/A | N/A |
| SQL Injection | 1 | SKIPPED | Keep skipped (no feature) | 0% | N/A |

**Progress Summary**:
- ✅ **Completed**: 5 tests unskipped (4 billing + 1 rate limiting)
- 🔧 **Fixed**: 14 tests that were failing (now passing)
- ⚠️ **Still Failing**: 4 tests (require implementation work)
- 📋 **Remaining Skipped**: 60 tests (down from 65)

**Quick Wins Remaining**: 5 tests can be unskipped with minimal work
**Estimated Coverage Gain from Remaining Quick Wins**: ~0%

---

## Additional Coverage Sources

To reach 70% from 59% (11 percentage point gain), we need:

1. **✅ Unskip the 5 completed quick win tests** → ~1% gain (DONE)
2. **🔧 Fixed 14 failing tests** → 0% gain (tests were already executing, now passing)
3. **⚠️ Fix 4 still-failing tests** → 0% gain (tests already executing, need implementation)
4. **📋 Unskip remaining 5 quick win tests** → ~0% gain (PCI, dark mode)
5. **📝 Write new tests for untested code** → ~10% gain needed

**Next Steps**:
1. ✅ **COMPLETED**: Fixed 14 failing tests (billing, webhooks, etc.)
2. ✅ **COMPLETED**: Unskipped 5 tests (4 billing + 1 rate limiting)
3. **IN PROGRESS**: Document 4 remaining failures that require implementation
4. **TODO**: Run coverage report to identify untested modules/functions
5. **TODO**: Prioritize critical paths (billing, security, API) for new tests
6. **TODO**: Focus on business logic over configuration/setup code

**Week 3 Test Suite Accomplishments (2025-10-29)**:
- Started: 4,504 passing, 19 failing, 65 skipped
- Ended: 4,518 passing, 4 failing, 60 skipped
- **Net Improvement**: +14 passing tests, -15 failing tests, -5 skipped tests
