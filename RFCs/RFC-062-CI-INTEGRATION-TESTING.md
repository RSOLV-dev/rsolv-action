# RFC-062: CI Integration Testing Infrastructure for RSOLV-action

**Status**: Draft
**Created**: 2025-10-06
**Author**: Dylan Fitzgerald

## Summary

Establish a comprehensive CI testing infrastructure for RSOLV-action integration tests that require live services, credentials, and full workflow orchestration. Currently, 40+ integration test files are excluded from the standard test suite and need proper GitHub Actions CI setup to run.

## Motivation

### Current State

**Unit Tests (Default Test Run)**:
- ~960 tests passing (87.7%)
- ~113 test files passing
- Run locally with mocking
- Fast execution (< 5 minutes)
- ✅ GREEN status achieved

**Integration Tests (Currently Excluded)**:
- ~40 test files excluded via `vitest.config.ts`
- Require live infrastructure:
  - RSOLV platform API access
  - Git repository operations
  - Vended credentials from platform
  - Full three-phase workflow orchestration
  - Real GitHub API interactions

### Problem

Integration tests currently fail when run locally because they require:
1. Live RSOLV platform backend (staging or production)
2. Valid API keys with proper permissions
3. Git repositories with actual issues
4. GitHub tokens with write permissions
5. Credential vending service access

Without a proper CI environment, these valuable tests cannot verify:
- End-to-end workflow correctness
- Integration between phases (SCAN → VALIDATE → MITIGATE)
- Real API contract compliance
- Credential vending and refresh
- Git operations in real repositories

## Excluded Test Files

The following test files are currently excluded via `vitest.config.ts` and need CI infrastructure:

### Phase Executor & Workflow Integration
- `src/modes/phase-executor/__tests__/validation-label-update.test.ts`
- `src/modes/phase-executor/__tests__/execute-all-phases-integration.test.ts`
- `src/modes/phase-executor/__tests__/mitigate-validation-flow.test.ts`
- `src/__tests__/modes/phase-executor-validation-integration.test.ts`
- `src/modes/__tests__/integration-all-modes.test.ts`
- `src/modes/__tests__/phase-executor.test.ts`
- `src/modes/__tests__/validation-only-mode.test.ts`
- `src/modes/__tests__/validation-mode-issue-number.test.ts`
- `src/modes/__tests__/validation-test-commit.test.ts`
- `src/modes/__tests__/vendor-filtering-all-phases.test.ts`

### Test-Aware Fix Generation
- `src/__tests__/test-aware-fix-validation/nodegoat-validation-failure.test.ts`
- `src/__tests__/test-aware-fix-validation/test-aware-integration.test.ts`

### Credential Management
- `tests/integration/credential-singleton.test.ts`
- `src/credentials/__tests__/manager.test.ts`

### AI Adapters & Claude CLI
- `src/ai/adapters/__tests__/claude-cli-mitigation.test.ts`
- `src/ai/adapters/__tests__/claude-code-cli-retry-vended.test.ts`
- `src/ai/adapters/__tests__/claude-code-cli-vended-credentials.test.ts`
- `src/ai/adapters/__tests__/claude-code-git-data-flow.test.ts`
- `src/ai/adapters/__tests__/claude-code-git-enhanced.test.ts`
- `src/ai/adapters/__tests__/claude-code-git-prompt.test.ts`
- `src/ai/adapters/__tests__/claude-code-git.test.ts`

### Git & GitHub Integration
- `src/github/__tests__/pr-git-authentication.test.ts`
- `src/external/__tests__/pr-integration.test.ts`
- `src/external/__tests__/api-client.test.ts`
- `src/ai/__tests__/git-based-processor-characterization.test.ts`
- `src/ai/__tests__/git-based-processor-test-mode.test.ts`
- `src/ai/__tests__/git-status-rsolv-ignore.test.ts`

### Scanner & AST Validation
- `test/scanner/ast-validator.test.ts`
- `src/scanner/__tests__/ast-validator-mocked.test.ts`
- `src/scanner/__tests__/issue-creator-max-issues.test.ts`

### Configuration & Token Management
- `src/config/__tests__/model-config.test.ts`
- `src/ai/__tests__/token-utils.test.ts`

### Pattern API
- `src/security/pattern-api-client.test.ts`
- `test/regression/pattern-availability.test.ts` (partially - API tests pass, needs pattern deduplication fix)

## Proposed Solution

### 1. GitHub Actions CI Workflow

Create `.github/workflows/integration-tests.yml`:

```yaml
name: Integration Tests

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  workflow_dispatch:

jobs:
  integration-tests:
    runs-on: ubuntu-latest
    timeout-minutes: 30

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run integration tests
        env:
          RSOLV_API_KEY: ${{ secrets.RSOLV_API_KEY }}
          RSOLV_API_URL: ${{ secrets.RSOLV_API_URL || 'https://api.rsolv-staging.com' }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          CLAUDE_CODE_API_KEY: ${{ secrets.CLAUDE_CODE_API_KEY }}
          RUN_INTEGRATION: 'true'
        run: npm run test:integration

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: integration-test-results
          path: |
            test-results/
            coverage/

      - name: Comment PR with results
        if: github.event_name == 'pull_request' && failure()
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '❌ Integration tests failed. Check the workflow logs for details.'
            })
```

### 2. Required GitHub Secrets

```bash
# RSOLV Platform Access
RSOLV_API_KEY=rsolv_xxx...  # Production API key for test customer
RSOLV_API_URL=https://api.rsolv.ai

# AI Provider Credentials
ANTHROPIC_API_KEY=sk-ant-xxx...
CLAUDE_CODE_API_KEY=xxx...

# GitHub Access (automatically provided, may need additional permissions)
GITHUB_TOKEN=ghp_xxx...
```

### 3. Test Commands

Add to `package.json`:

```json
{
  "scripts": {
    "test": "./run-tests.sh",
    "test:unit": "vitest run",
    "test:integration": "RUN_INTEGRATION=true vitest run",
    "test:all": "npm run test:unit && npm run test:integration"
  }
}
```

### 4. Vitest Configuration

Already implemented in `vitest.config.ts`:

```typescript
// Skip integration tests unless explicitly enabled
...(process.env.RUN_INTEGRATION !== 'true' ? [
  '**/tests/integration/**',
  '**/*integration*.test.ts',
  '**/phase-executor/**/*.test.ts',
  '**/test-aware-fix-validation/**/*.test.ts'
] : [])
```

## Infrastructure Requirements

### Staging Environment Access
- **RSOLV Platform**: Staging instance at `api.rsolv-staging.com`
- **Test Customer Account**: Dedicated customer with appropriate quotas
- **API Key**: Fresh key created: `rsolv_GD5KyzSXvKzaztds23HijV5HFnD7ZZs8cbF1UX5ks_8`

### Test Repository
- **Dedicated Test Repo**: Create `RSOLV-dev/test-integration-repo`
- **Known Issues**: Pre-created issues for validation
- **Write Access**: GitHub token with issue/PR creation permissions

### Credential Vending
- **Platform Support**: Credential vending endpoint must be accessible
- **Test Mode**: Platform recognizes test customer and provides temporary credentials
- **Refresh Logic**: Tests can handle credential expiration and refresh

## Implementation Plan

### Phase 1: Basic CI Setup (1 day)
- [ ] Create GitHub Actions workflow
- [ ] Configure secrets in GitHub repository
- [ ] Test basic workflow execution
- [ ] Verify unit tests still run separately

### Phase 2: Integration Test Categories (2-3 days)
- [ ] Phase executor tests
- [ ] Credential management tests
- [ ] AI adapter tests with Claude CLI
- [ ] Git/GitHub integration tests

### Phase 3: Advanced Testing (2-3 days)
- [ ] Test-aware fix generation workflows
- [ ] Full three-phase orchestration
- [ ] Pattern API validation
- [ ] AST validation with platform

### Phase 4: Optimization (1-2 days)
- [ ] Parallel test execution
- [ ] Test result caching
- [ ] Failure reporting improvements
- [ ] PR comment integration

## Success Metrics

- ✅ All 40+ integration test files passing in CI
- ✅ < 15 minute total integration test run time
- ✅ Unit tests remain fast (< 5 minutes) and independent
- ✅ Clear separation between unit and integration test runs
- ✅ Integration tests catch real API/workflow issues before production

## Test Suite Architecture

### Unit Tests (Default - Always Run)
```bash
npm test                    # Runs unit tests only
npm run test:unit           # Explicit unit test run
```

**Characteristics**:
- Fast (< 5 minutes)
- Run locally without infrastructure
- Mocked dependencies
- Test business logic and algorithms
- 960+ tests passing

### Integration Tests (CI Only - Gated)
```bash
RUN_INTEGRATION=true npm test     # Run integration tests
npm run test:integration           # Explicit integration run
```

**Characteristics**:
- Slower (10-15 minutes)
- Require live services
- Real API calls and credentials
- Test end-to-end workflows
- 40+ test files excluded from default run

### Full Test Suite (CI + Pre-release)
```bash
npm run test:all            # Unit + Integration
```

**When to run**:
- Before major releases
- Weekly scheduled CI runs
- Post-deployment verification
- Breaking change validation

## Known Issues to Address

1. **Pattern Deduplication Bug**:
   - 162 patterns returned but only 132 unique IDs
   - Suggests patterns loaded from multiple sources creating duplicates
   - Affects: `test/regression/pattern-availability.test.ts`

2. **AST Validator Mocking**:
   - Some tests expect real platform AST responses
   - May need platform mock server for offline testing
   - Affects: `test/scanner/ast-validator.test.ts`

3. **Git Operations in Docker**:
   - Act/Docker-in-Docker environments need special handling
   - Already fixed in v3.7.46 but may need verification
   - Affects: Git-based processor tests

## Alternatives Considered

### 1. Docker Compose Test Environment
**Pros**: Can run integration tests locally
**Cons**:
- Requires maintaining full platform stack
- Complex setup and maintenance
- Doesn't test real platform API contracts
**Decision**: Rejected - CI-based approach is simpler and tests real services

### 2. Mock Everything
**Pros**: Fast, no infrastructure needed
**Cons**:
- Doesn't test real integration
- Mocks drift from actual behavior
- Miss contract changes
**Decision**: Rejected - Need real integration testing

### 3. Separate Integration Test Repository
**Pros**: Clear separation, independent CI
**Cons**:
- Harder to maintain
- Tests separated from code
- Duplication of infrastructure
**Decision**: Rejected - Keep tests with code using env var gating

## References

- Current test configuration: `vitest.config.ts`
- Test runner script: `run-tests.sh`
- RFC-059: Local Testing with Act (for E2E workflows)
- Testing documentation: `TESTING.md` (needs update for integration tests)

## Open Questions

1. Should integration tests run on every PR or just main/develop?
2. Do we need a dedicated test repository or use existing RSOLV-dev repos?
3. Should we implement integration test result caching?
4. What's the budget for integration test run time (15 min? 30 min?)?
5. Do we need staging environment auto-setup or manual configuration?

## Next Steps

1. **Review and approve this RFC**
2. **Create GitHub Actions workflow** (Phase 1)
3. **Configure secrets** in RSOLV-action repository
4. **Enable integration test runs** for CI
5. **Update TESTING.md** with integration test documentation
6. **Monitor and optimize** test run times
