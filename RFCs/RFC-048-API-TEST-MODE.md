# RFC-048: API Test Mode

**Status:** Draft  
**Created:** 2025-08-28  
**Author:** Dylan Fitzgerald  

## Problem Statement

Current testing of the RSOLV API requires:
- Real forge accounts (GitHub integration)
- External API dependencies
- Complex test fixtures and setup
- Database state management
- Cache pollution risks

This creates friction for:
- Local development
- CI/CD pipelines  
- Integration testing
- Developer onboarding

## Proposed Solution

Implement a **Test Mode** for the RSOLV API that provides deterministic, isolated validation without external dependencies.

### Core Design

1. **Activation**: API keys with specific prefixes trigger test mode
   - `test_*`
   - `rsolv_test_*`
   - `demo_*`

2. **Environment Control**: Two-layer configuration
   ```elixir
   defp test_mode_enabled? do
     FunWithFlags.enabled?(:api_test_mode) ||
     Application.get_env(:rsolv, :test_mode_enabled, false)
   end
   ```

3. **Environment Restrictions**:
   - **Enabled**: Local, staging, CI environments
   - **Disabled**: Production (returns `RSOLV_AUTH_1003` error)

## Technical Design

### Validation Logic

Test mode uses the **existing production validation logic** (`SafePatternDetector`):

```elixir
defmodule RsolvWeb.Api.V1.TestMode do
  alias RsolvWeb.Api.V1.SafePatternDetector
  
  def validate_in_test_mode(vulnerability, files) do
    # No forge account lookup
    # No external API calls
    # Use production validation rules
    is_safe = SafePatternDetector.is_safe_pattern?(
      vulnerability.type,
      vulnerability.code,
      %{language: detect_language(vulnerability.file_path)}
    )
    
    build_test_response(vulnerability, is_safe)
  end
end
```

### Response Format

Test mode responses include verbose metadata for debugging:

```json
{
  "validated": [...],
  "stats": {...},
  "_testMode": {
    "active": true,
    "rulesApplied": "SafePatternDetector.is_safe_pattern?(:sql_injection, ...)",
    "result": "false_positive",
    "reason": "Parameterized query detected",
    "cacheBypass": true,
    "environment": "staging"
  }
}
```

### Cache Behavior

- **Default**: Bypass cache entirely (no reads, no writes)
- **Optional**: Enable via `X-Test-Cache: true` header for cache testing

### Rate Limiting

No rate limits in test mode (simplifies testing).

### Telemetry

Normal telemetry with `test_mode: true` flag for filtering:

```elixir
:telemetry.execute(
  [:rsolv, :validation, :request],
  %{duration: duration, ...},
  %{
    result: :success,
    test_mode: true,
    customer_id: "test_mode"
  }
)
```

## Self-Documentation Endpoint

`GET /api/v1/test-mode/info`:

```json
{
  "enabled": true,
  "environment": "staging",
  "availableKeys": [
    "test_*",
    "rsolv_test_*", 
    "demo_*"
  ],
  "features": {
    "cache": "bypassed (use X-Test-Cache header to enable)",
    "rateLimits": "disabled",
    "telemetry": "enabled with test_mode flag"
  },
  "examples": {
    "curl": "curl -H 'X-API-Key: test_123' https://api-staging.rsolv.dev/api/v1/validate"
  }
}
```

## Implementation Strategy (TDD)

### Phase 1: RED - Write Failing Tests

```elixir
describe "API Test Mode" do
  test "detects test mode from api key prefix"
  test "returns verbose metadata in test mode"
  test "bypasses cache in test mode by default"
  test "uses SafePatternDetector for validation"
  test "returns RSOLV_AUTH_1003 in production"
  test "respects FunWithFlags toggle"
  test "provides info endpoint"
end
```

### Phase 2: GREEN - Minimal Implementation

1. Add test key detection to auth pipeline
2. Create `TestMode` module with validation logic
3. Add response metadata
4. Implement info endpoint

### Phase 3: REFACTOR - Architecture Improvements

This phase provides opportunity to:

1. **Extract Common Auth Logic**
   - Consolidate API key validation across controllers
   - Create shared auth pipeline

2. **Unify Validation Controllers**
   - Merge common logic between `vulnerability_validation_controller.ex` and `vulnerability_validation_controller_with_cache.ex`
   - Extract shared validation logic

3. **Standardize Response Building**
   - Create consistent response format helpers
   - Standardize error responses

4. **Centralize Cache Decisions**
   - Extract cache bypass logic
   - Make cache behavior more configurable

## API Documentation

All test mode endpoints will be documented using `open_api_spex`:

```elixir
@operation :validate
@parameters [
  api_key: [
    in: :header, 
    required: true,
    pattern: ~r/^(test_|rsolv_test_|demo_|rsolv_)/,
    description: "API key (test_ prefix enables test mode)"
  ]
]
@responses [
  200: {"Validation successful", "application/json", ValidationResponse},
  401: {"Invalid API key", "application/json", ErrorResponse}
]
```

## Tests Enabled by This RFC

### Tests That Can Be Re-enabled with RFC-048 Implementation (30+ tests)

**REVISED ANALYSIS (2025-08-28)**: After detailed examination, 30 tests would benefit from test mode, not 27 as originally estimated.

**ADDITIONAL OPPORTUNITY (2025-08-28)**: The Pattern API E2E test (`src/__tests__/pattern-api-e2e.test.ts`) currently uses MSW for mocking but would be an ideal candidate for RFC-048 Test Mode. Once implemented, this test could use real fetch with test API keys (e.g., `rsolv_test_*` or `test_*` prefixes) for safe, deterministic API testing against the actual test mode endpoint. This would provide superior integration testing compared to mocking while remaining isolated from production.

These tests are currently skipped but would be enabled once test mode is available:

#### AST Service Tests (20 tests)
- `test/ast-staging-integration-e2e.test.ts` - AST Staging Integration (1 suite)
- `test/ast-service-verification.test.ts` - AST Service Verification (1 suite) 
- `test/server-ast-integration.test.ts` - Server AST Integration (5 tests)
  - "should use server-side AST service endpoint"
  - "should detect Python SQL injection via server AST"
  - "should detect Ruby command injection via server AST"
  - "should detect PHP XSS via server AST"
  - "should achieve >90% accuracy on mixed language corpus"
- `test/server-ast-red-phase.test.ts` - Red Phase AST Tests (3 tests)
- `test/server-ast-green-phase.test.ts` - Green Phase Implementation (1 test)
- `src/scanner/__tests__/ast-validator-live-api.test.ts` - Live API Validation (1 suite)
- `test/detector-v3-python.test.ts` - Python detection via server AST (1 test)
- `src/security/analyzers/__tests__/fallback-strategy.test.ts` - AST Fallback Strategy (7 tests)
  - Tests failover from AST to regex when service unavailable
  - Tests timeout handling and error recovery
  - Tests cache behavior during fallback scenarios

#### API Integration Tests (5 tests)
- `test/integration/api-endpoints.test.ts` - Real API Endpoint Integration (2 suites)
  - Pattern API endpoint tests
  - Language-specific pattern requests
  - **Note**: These make REAL API calls and would benefit from test mode
- `src/ai/__tests__/vended-credential-e2e.test.ts` - Credential Vending (3 suites)

#### Validation Tests (5 tests)
- `src/ai/__tests__/fix-iteration-java-php.test.ts` - Java/PHP Fix Validation (2 tests)
- `src/ai/__tests__/adaptive-test-generator-php.test.ts` - Pest framework generation (2 tests)
- `test/credentials/credential-lifecycle.test.ts` - Credential refresh (1 test)
  - **Note**: May still be timing-sensitive even with test mode

### Tests Unrelated to RFC-048 (36 tests as of 2025-08-28)

**REVISED ANALYSIS**: After implementing Claude Max auto-detection and fixing mocked tests, only 36 tests remain that wouldn't benefit from test mode.

These tests are skipped for other reasons and won't be affected by test mode:

#### External AI Provider Tests (25 tests)
- `src/ai/__tests__/llm-adapters-live.test.ts` - Live LLM tests (5 suites)
  - OpenAI, Anthropic API (not CLI), Cohere, Ollama
  - Require actual API keys and incur costs
- `src/ai/__tests__/claude-code-live.test.ts` - Claude Code Live (4 tests)
  - **UPDATE**: Now auto-enabled with Claude Max subscription detection
- `src/ai/adapters/__tests__/claude-code-integration.test.ts` - Claude CLI (3 tests)
  - **UPDATE**: Now auto-enabled with Claude Max subscription detection

#### Third-Party Platform Integrations (5 tests)
- `tests/platforms/jira/jira-integration.test.ts` - Jira Integration (1 suite)
- `src/platforms/linear/linear-integration.test.ts` - Linear Integration (1 suite)
- `src/platforms/linear/linear-adapter.test.ts` - Linear Adapter (1 suite)
- **Note**: Require actual platform accounts and API credentials

#### Unimplemented Features (2 tests)
- `src/modes/__tests__/mitigation-only-mode.test.ts` - Multiple issue batch processing (2 tests)
  - Feature not yet implemented in codebase
  - Tests are placeholders for future functionality

#### Test Infrastructure Issues (1 test)
- `src/__tests__/pattern-api-e2e.test.ts` - Pattern API E2E (1 suite)
  - Conflicts with global fetch mock in vitest
  - Needs isolation or MSW (Mock Service Worker) to fix

#### Timing-Sensitive Tests (1 test)
- `test/credentials/credential-lifecycle.test.ts` - Auto-refresh expired credentials (1 test)
  - May work with test mode but timing makes it fragile

#### Already Fixed (no longer skipped)
- `tests/integration/container.test.ts` - ✅ Fixed in this session (fully mocked)
- Claude Code tests - ✅ Auto-enabled with Max subscription

## Implementation Impact

When RFC-048 is implemented:
- **30 tests** can be immediately re-enabled using test mode API keys
- **36 tests** will remain skipped (down from 66 currently, thanks to Claude Max)
- This represents a **45.5% reduction** in currently skipped tests
- Combined with Claude Max auto-detection: **52% total reduction** from original 70 tests

The test mode will particularly benefit:
1. Multi-language AST validation testing
2. API integration testing without production impact
3. CI/CD pipeline reliability
4. Developer onboarding and local testing

## Security Considerations

1. **Production Protection**: Test mode completely disabled in production
2. **No State Pollution**: Test mode doesn't write to production cache/database
3. **Clear Identification**: Responses clearly marked as test mode
4. **Audit Trail**: Telemetry tracks all test mode usage

## Benefits

1. **Developer Experience**
   - Zero setup required
   - Instant testing capability
   - Clear debugging information

2. **Testing**
   - Deterministic results
   - No external dependencies
   - Isolated from production

3. **Architecture**
   - Opportunity to refactor and improve code organization
   - Enforces API documentation standards
   - Reduces technical debt

## Migration Path

1. **Phase 1**: Implement test mode detection and basic functionality
2. **Phase 2**: Add comprehensive OpenAPI documentation
3. **Phase 3**: Refactor controllers to share common logic
4. **Phase 4**: Migrate existing tests to use test mode

## Current Test Suite Analysis (2025-08-28)

Based on analysis of the RSOLV-action test suite, the following tests would benefit from Test Mode:

### Tests to Migrate After Implementation (Currently Failing/Skipped):
- **AST Service Verification Tests** - Need deterministic API responses
- **E2E Integration Tests** - Currently skipped due to lack of API access
- **Staging API Tests** - Require forge accounts that test mode would eliminate
- **Platform Integration Tests** - Need predictable validation responses

### Tests Working Without Test Mode (Should Fix Now):
- **ElixirASTAnalyzer Unit Tests** - Configuration validation issues
- **Fallback Strategy Tests** - Mock setup problems
- **SecurityDetectorV3 Tests** - Test expectation mismatches

Current test suite metrics:
- Overall Pass Rate: 78.24%
- Integration Tests: 76.7% (will improve with test mode)
- Server/Platform Tests: 47.1% (primary beneficiary of test mode)

## Success Metrics

- Reduction in test setup complexity
- Faster CI/CD pipeline execution
- Improved developer onboarding time
- Increased API documentation coverage

## Future Enhancements

- Test profiles (e.g., `X-Test-Profile: high-vulnerability`)
- Test data generation endpoints
- Performance testing mode with simulated latency
- **Docker Compose for Local Development**: Capture local test infrastructure (test API, database, cache) in docker-compose.yml for consistent development environment. This would enable developers to run integration tests locally with the same test mode behavior as CI/CD pipelines

## Decision

*[To be completed after review]*

## References

- ADR-016: AST Validation Architecture
- RFC-042: AST False Positive Reduction
- RFC-046: False Positive Caching TDD