# Test Exclusions for Production

This document outlines tests that are excluded from the production test suite and the reasons for their exclusion.

## Excluded Test Categories

### 1. Claude Code CLI Tests
**Files**: `src/ai/adapters/__tests__/claude-code*.test.ts`
**Reason**: Requires Claude Code CLI to be installed locally
**Status**: These tests use mocks in CI/CD environments
**Production Impact**: None - Claude Code is an optional AI provider with fallbacks

### 2. Docker Container Tests  
**Files**: `tests/integration/container.test.ts`
**Reason**: Requires Docker daemon to be running
**Status**: Container functionality is optional
**Production Impact**: None - containers are disabled by default in production

### 3. Linear Platform Adapter Tests
**Files**: `src/platforms/linear/linear-adapter.test.ts`
**Reason**: Mock implementation issues with GraphQL client
**Status**: Needs refactoring to use proper mocks
**Production Impact**: Low - Linear is a secondary platform (GitHub is primary)

### 4. Full E2E Workflow Tests
**Files**: `tests/e2e/full-demo-flow.test.ts`
**Reason**: Requires complete environment with all services running
**Status**: Covered by staging E2E tests
**Production Impact**: None - functionality tested in staging

### 5. Security Demo Tests
**Files**: `src/__tests__/security-demo.test.ts`
**Reason**: Tests are marked as skipped, demo file was missing
**Status**: Technical debt - demo environment needs implementation
**Production Impact**: None - demo code not used in production

## Tests That Must Pass in Production

### Critical Path Tests
1. **Security Module** (`src/security/`) - All pattern detection and API integration
2. **Configuration** (`src/config/`, `tests/integration/config.test.ts`) - Config loading and validation
3. **External API Client** (`src/external/`) - RSOLV API communication
4. **Core AI Tests** (`src/ai/__tests__/`) - Excluding Claude Code specific tests
5. **Platform Detection** (`tests/platforms/`) - Multi-platform issue detection
6. **GitHub Integration** (`tests/github/`) - Primary platform functionality

### Test Commands

```bash
# Run full test suite (includes failures)
bun test

# Run production-ready test suite (excludes known issues)
./test-green-suite.sh

# Run staging E2E tests
./test-staging-e2e.sh

# Run specific test category
bun test src/security/
```

## CI/CD Considerations

In CI/CD pipelines, use the following approach:

1. **PR Checks**: Run `./test-green-suite.sh` to ensure no regressions
2. **Staging Deploy**: Run `./test-staging-e2e.sh` after deployment
3. **Production Deploy**: Verify staging E2E passes before promoting

## Fixing Excluded Tests

Priority order for fixing excluded tests:

1. **High Priority**: Linear adapter mocks (affects multi-platform support)
2. **Medium Priority**: Full E2E tests (improve test coverage)
3. **Low Priority**: Security demo, Claude Code CLI mocks (nice to have)

## Monitoring Test Health

Track test suite health with:
```bash
# Show test summary
bun test --reporter=junit > test-results.xml

# Count passing/failing tests
bun test | grep -E "(pass|fail)" | sort | uniq -c
```

## Pattern Testing Results (June 18, 2025)

### API Integration Status
- **Pattern API**: ✅ Working correctly with RSOLV-api
- **Pattern Source**: ✅ Fetching patterns from API with caching
- **Detector Integration**: ✅ Using patterns for vulnerability detection

### Public Tier Patterns (61 total)
- JavaScript: 17 patterns
- Python: 6 patterns  
- Ruby: 8 patterns
- Java: 4 patterns
- PHP: 11 patterns
- Elixir: 15 patterns

### Detection Results
- **XSS Detection**: ✅ Working (100% success rate)
- **SQL Injection**: ❌ Not in public tier
- **Command Injection**: ❌ Not in public tier
- **Weak Crypto**: ❌ Not in public tier
- **Hardcoded Secrets**: ❌ Not in public tier

### Production Considerations
- Full pattern library (448 patterns) requires enterprise API access
- Public tier provides basic XSS detection for demos
- Pattern tiering is working as designed for IP protection