# Flaky Tests Analysis

## Summary
- Test failures vary from 17 to 86 across runs
- Many tests appear to have race conditions or timing dependencies

## Categories of Flaky Tests

### 1. Parser-Related Tests (Most Flaky)
**File**: `test/rsolv/ast/multi_language_parsing_test.exs`
- Appears in all 3 runs with different subsets failing
- Issue: Parser processes may not be ready when tests start
- Fix Applied: Added `async: false` and `ensure_parsers_ready()`

### 2. Fallback Strategy Tests
**File**: `test/rsolv/ast/fallback_strategy_test.exs`
- 17 tests failed in run 2, but 0 in runs 1 and 3
- Extreme flakiness suggests initialization or module loading issues

### 3. Controller Tests
Various controller tests fail inconsistently:
- `PageControllerAnalyticsTest`
- `PageControllerAdminNotificationTest`
- `WebhookControllerTest`
- `DashboardControllerTest`

### 4. Code Retention Tests
**File**: `test/rsolv/ast/code_retention_test.exs`
- 10 tests failed in run 2 only
- Already fixed by switching to DataCase

### 5. Email/Integration Tests
- `EmailFlowTest`
- `EmailDeliveryTest`
- `ConvertKitIntegrationTest`
- Likely related to async execution and shared state

## Root Causes

1. **Async Test Execution**: Tests running in parallel compete for resources
2. **Process Initialization**: Services/parsers not ready when tests start
3. **Shared State**: Tests may be affecting each other through ETS tables or database
4. **External Dependencies**: Parser processes, port communication

## Recommendations

1. **Immediate Fixes**:
   - Set `async: false` on all flaky test modules
   - Add proper setup blocks to ensure services are ready
   - Add process monitoring instead of sleeps

2. **Long-term Fixes**:
   - Implement proper test isolation
   - Use mocks for external parsers in unit tests
   - Create separate integration test suite for parser tests
   - Add retry logic for inherently flaky operations

3. **CI Strategy**:
   - Tag known flaky tests with `@tag :flaky`
   - Run flaky tests separately with retries
   - Monitor flakiness trends over time