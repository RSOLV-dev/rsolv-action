# E2E Tests

This directory contains end-to-end tests for the RSOLV action, including test integration workflows for various languages and frameworks.

## Test Categories

### 1. Test Integration E2E Tests

#### Ruby/RSpec with RailsGoat (`railsgoat-ruby-rspec.test.ts`)

Tests the complete RSOLV workflow for Ruby projects using RSpec:

**What it tests:**
- Clone RailsGoat repository
- Run RSOLV SCAN mode (detect SQL injection or mass assignment vulnerabilities)
- Run RSOLV VALIDATE mode (generate RED tests using RSpec)
- Verify test integration:
  - Tests integrated into existing spec files (NOT `.rsolv/tests/`)
  - Tests use RSpec conventions (describe, it, expect, before hooks)
  - Tests use realistic attack vectors from `REALISTIC-VULNERABILITY-EXAMPLES.md`
  - Tests FAIL on vulnerable code (RED test behavior)
  - Existing tests still PASS (no regressions)
  - Backend AST method used for integration
  - Proper 2-space indentation maintained
- Run RSOLV MITIGATE mode (apply fixes)
- Verify security test now PASSES after fix

**Prerequisites:**
```bash
# Backend with Ruby/RSpec AST integration support
export RSOLV_API_URL=https://api.rsolv.com
export RSOLV_API_KEY=your_api_key

# Git and Ruby available in PATH
ruby --version
git --version
```

**Running the test:**
```bash
# Run Ruby E2E test
RUN_E2E=true RSOLV_API_URL=https://api.rsolv.com RSOLV_API_KEY=xxx npm run vitest tests/e2e/railsgoat-ruby-rspec.test.ts

# Or use the shortcut (if available)
npm run test:e2e:ruby
```

**Expected vulnerability detection:**
- SQL Injection: `User.where("id = '#{params[:user][:id]}'")`
- Attack vector: `5') OR admin = 't' --'`
- Mass Assignment: `@user.update(params[:user])` allowing `admin: true`

**Test timeout:** 120 seconds (full clone + scan + validate + mitigate workflow)

#### Test Integration Client (`test-integration-e2e.test.ts`)

Tests the TestIntegrationClient against the live backend API:

**What it tests:**
- Complete workflow: analyze → generate → validate
- Error handling (401, 422, 500, timeouts)
- Retry logic with exponential backoff
- Framework-specific integration (Vitest, Jest, RSpec, pytest)
- AST integration vs fallback append strategies

**Running the test:**
```bash
RSOLV_API_URL=https://api.rsolv-staging.com TEST_API_KEY=xxx npm test test-integration-e2e
```

### 2. Pattern API Integration Tests

The pattern API integration tests verify pattern fetching and tier access.

#### Running E2E Tests Manually

1. Start the RSOLV API:
   ```bash
   cd RSOLV-api
   mix phx.server
   ```

2. Run the standalone E2E test:
   ```bash
   cd RSOLV-action
   bun run test-pattern-api-real.ts
   ```

### Test Coverage

1. **Unit Tests (RSOLV-api)** - 15 tests, 0 failures:
   - `tier_access_test.exs` - Tests cumulative tier access
   - `tier_determination_test.exs` - Tests string/atom handling
   - `accounts_test.exs` - Tests customer configuration

2. **E2E Tests (manual)** - 35 tests passed:
   - Pattern fetching with authentication
   - Multiple pattern tier access
   - Language-specific pattern fetching
   - AST-enhanced pattern retrieval
   - Tier-specific access validation

3. **Test Integration E2E (Phase 4)** - Ruby/RSpec:
   - Full SCAN → VALIDATE → MITIGATE workflow
   - RSpec test generation and integration
   - Attack vector validation (SQL injection, mass assignment)
   - Backend AST integration verification
   - Test syntax and convention validation

## Running All E2E Tests

```bash
# Run all E2E tests (requires backend access)
RUN_E2E=true RSOLV_API_URL=https://api.rsolv.com RSOLV_API_KEY=xxx npm test tests/e2e/

# Run specific E2E test category
RUN_E2E=true npm test tests/e2e/railsgoat-ruby-rspec.test.ts
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `RUN_E2E` | Yes | Set to `true` to enable E2E tests |
| `RSOLV_API_URL` | Yes | Backend API URL (staging or production) |
| `RSOLV_API_KEY` | Yes | API authentication key |
| `TEST_API_KEY` | Optional | Alternative to RSOLV_API_KEY for some tests |
| `GITHUB_TOKEN` | Optional | For GitHub API integration tests |

## Known Issues

The global fetch mock in `setup-tests.ts` returns empty objects for all JSON responses, which breaks real API calls. This affects all tests that need to make actual HTTP requests.

**Workaround:** E2E tests are excluded by default in vitest.config.ts and only run when `RUN_E2E=true`.

## Future Improvements

1. ✅ Add Ruby/RSpec E2E test with RailsGoat (Phase 4 - COMPLETED)
2. Add Python/pytest E2E test with DVPWA (Phase 4 - Planned)
3. Add JavaScript/Vitest E2E test with NodeGoat (Phase 4 - Planned)
4. Create unified E2E runner script for all language tests
5. Implement a more sophisticated mock that can pass through certain URLs