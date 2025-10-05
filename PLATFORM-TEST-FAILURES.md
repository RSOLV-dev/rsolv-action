# Platform Test Failures - Work in Progress

**Status**: 42 failures remaining (down from 53)
**Last Run**: 2025-10-05 19:50:33
**Branch**: rfc-060-executable-validation-tests

## Progress Summary

### ✅ Fixed (11 failures)
1. **forge_account_id type casting** - Fixed validation cache queries to convert integers to strings
2. **API error message text** - Updated test expectation from "Missing API key" to "Authentication required"

### 🔄 Remaining Failures (42)

## Failure Categories

### 1. API Error Response Format Mismatch (~30 failures)

**Root Cause**: Tests expect structured error responses with codes and request IDs, but ApiAuthentication plug returns simple format.

**Expected Format**:
```json
{
  "error": {
    "code": "INVALID_API_KEY",
    "message": "Invalid or expired API key"
  },
  "requestId": "GGutXuJyw5pJuIwAAIWE"
}
```

**Current Format**:
```json
{
  "error": "Invalid API key",
  "message": "The provided API key is invalid or expired"
}
```

**Affected Tests**:
- test/rsolv_web/controllers/api/v1/ast_controller_test.exs:60 (validates API key)
- test/rsolv_web/controllers/api/v1/ast_controller_test.exs:47 (requires authentication)
- test/rsolv_web/controllers/api/v1/pattern_controller_test.exs (multiple)
- test/rsolv_web/controllers/api/v1/ast_pattern_serialization_test.exs (multiple)
- test/rsolv_web/controllers/credential_vending_*.exs (multiple)
- test/rsolv_web/controllers/credential_controller_test.exs (multiple)

**Fix Strategy**:
1. Update ErrorJSON to support structured error format with error codes
2. Update ApiAuthentication plug to include request ID and error codes
3. Create error code constants for different auth failure scenarios

**Files to Modify**:
- `lib/rsolv_web/controllers/error_json.ex` - Add structured error rendering
- `lib/rsolv_web/plugs/api_authentication.ex` - Include request IDs and error codes

### 2. Ecto.Query.CastError - Integer vs String (~8 failures)

**Root Cause**: Similar to forge_account_id, other fields may be defined as strings but tests pass integers.

**Affected Tests**:
- test/rsolv/validation_cache_invalidation_test.exs (multiple)
- test/rsolv/validation_cache_integration_test.exs (multiple)

**Fix Strategy**:
1. Search for other fields that might have integer/string mismatch
2. Apply same normalization pattern as forge_account_id
3. Check if ValidationCache functions need additional type conversion

**Investigation Needed**:
- Review all ValidationCache query functions
- Check cached_validation schema for other string-typed ID fields

### 3. Analytics Partitioning Errors (~2 failures)

**Error**: `ERROR 23514 (check_violation) no partition of relation "analytics_events" found for row`

**Affected Tests**:
- test/rsolv/analytics_partition_test.exs:XX (automatic partition creation)
- test/rsolv/analytics_partition_test.exs:XX (concurrent partition creation)

**Fix Strategy**:
1. Check analytics_events table partitioning setup
2. Ensure partition creation function works in test environment
3. Verify test database has proper partition setup

**Investigation Needed**:
- Check priv/repo/migrations for analytics partitioning migration
- Test `create_analytics_partition_if_not_exists` function

### 4. Admin/LiveView Issues (~6 failures)

**Root Cause**: Multiple issues with admin authentication and LiveView selectors

**Sub-categories**:

#### 4a. Admin Authentication Redirects
- test/rsolv_web/live/admin/login_live_integration_test.exs (3 failures)
- Expected behavior: Redirect to auth endpoint
- Actual: Different redirect or error

#### 4b. LiveView CSS Selectors
- test/rsolv_web/live/admin/customer_live_test.exs (5 failures)
- Error: `got invalid css selector: a[phx-click=edit][phx-value-id=85296]`
- Issue: CSS selector format incorrect for LiveView

**Fix Strategy**:
1. Admin auth: Check admin authentication plug configuration
2. CSS selectors: Update selector format to use proper LiveView syntax
3. May need to use `#` prefix for Phoenix.LiveViewTest helpers

### 5. Miscellaneous (~2 failures)

**Remaining individual failures**:
- test/rsolv/integration/php_pattern_ast_test.exs:XX (PHP pattern AST enhancement)
- test/rsolv_web/live/admin/customer_live/edit_test.exs:XX (Edit updates customer)

**Investigation Needed**:
- Review individual test failures for unique issues

## Implementation Plan

### Phase 1: API Error Response Format (Highest Impact)
**Estimated fixes**: ~30 tests
**Effort**: 1-2 hours

1. Create error code module with constants
2. Update ErrorJSON.render/2 for structured format
3. Update ApiAuthentication plug to use new format
4. Add request_id to error responses

### Phase 2: Remaining Type Casting Issues
**Estimated fixes**: ~8 tests
**Effort**: 30 minutes

1. Search ValidationCache for remaining casting issues
2. Apply normalization pattern
3. Update affected query functions

### Phase 3: Analytics Partitioning
**Estimated fixes**: ~2 tests
**Effort**: 30 minutes

1. Review partitioning setup
2. Fix partition creation in tests
3. Ensure proper test database configuration

### Phase 4: Admin/LiveView
**Estimated fixes**: ~6 tests
**Effort**: 1 hour

1. Fix admin authentication redirects
2. Update CSS selectors for LiveView
3. Test admin functionality

### Phase 5: Miscellaneous
**Estimated fixes**: ~2 tests
**Effort**: 30 minutes

1. Fix PHP pattern test
2. Fix customer edit test

## Next Steps

1. **Start with Phase 1** (API Error Response Format) - highest impact
2. **Create error code constants** in new module
3. **Update ErrorJSON** to support both old and new formats during transition
4. **Update ApiAuthentication** plug systematically
5. **Run tests after each phase** to verify progress

## Testing Strategy

After each phase:
```bash
# Run all tests
mix test

# Run specific test file
mix test test/rsolv_web/controllers/api/v1/ast_controller_test.exs

# Run specific test
mix test test/rsolv_web/controllers/api/v1/ast_controller_test.exs:60
```

## Notes

- All changes are on branch: `rfc-060-executable-validation-tests`
- RSOLV-action tests are already green
- This work is prerequisite for RFC-060 implementation
- Focus on green baseline before proceeding with PhaseDataClient work
