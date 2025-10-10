# RFC-060 Phase 4.1: End-to-End Workflow Testing

## Overview

This document describes the end-to-end integration testing setup for RFC-060, which validates the full SCAN → VALIDATE → MITIGATE workflow.

## Scope Clarification

**Phase 4.1 Scope**:
- Uses **mocked services** for all external dependencies (GitHub API, AI services, nodegoat)
- Validates workflow logic and data flow between phases
- Ensures proper usage of PhaseDataClient API, TestRunner, and ExecutableTestGenerator

**Phase 4.3 Scope** (Future):
- Will use **real nodegoat-vulnerability-demo** repository
- Will perform actual scanning, test generation, and fixing
- Will validate against real vulnerabilities

## Test Suite Location

**File**: `tests/integration/rfc-060-workflow.test.ts`

## Test Coverage

The integration test suite validates the following workflow stages:

### 1. SCAN Phase Tests
- **Creates GitHub issues**: Verifies that vulnerabilities discovered during scanning create GitHub issues
- Validates that `maxIssues` configuration is respected
- Confirms issue metadata (number, URL) is correctly returned

### 2. VALIDATE Phase Tests
- **Generates RED tests**: Verifies that the validation phase can generate security tests
- **Executes tests and stores results**: Ensures test execution results are persisted to disk
- **Stores validation metadata**: Confirms validation scores (pattern match, AST, contextual) are saved
- Tests that RED tests are expected to fail initially (proving vulnerability exists)

### 3. MITIGATE Phase Tests
- **Retrieves validation metadata**: Verifies mitigation can access validation data
- **Includes test in prompt**: Ensures generated tests are included in AI fix prompts
- **Uses validation scores**: Confirms trust scores are calculated from validation metadata

### 4. Full Workflow Integration
- **End-to-end flow**: Tests complete SCAN → VALIDATE → MITIGATE pipeline
- Verifies proper data flow between phases
- Validates issue counting and success metrics

## Running the Tests

### Prerequisites

1. Install dependencies:
   ```bash
   bun install
   ```

2. Set required environment variables (optional for tests, mocked by default):
   ```bash
   export GITHUB_TOKEN=your-token
   export RSOLV_API_KEY=your-api-key
   ```

### Run Integration Tests

The project includes memory-safe test runners that handle integration tests properly:

```bash
# Using npm scripts (recommended - handles memory constraints)
npm run test:memory

# Run with coverage
npm run test:coverage

# For CI environments (memory-safe with JSON output)
npm run test:ci

# Watch mode for development
npm run test:watch
```

### Direct vitest commands (alternative)

```bash
# Run all integration tests
RUN_INTEGRATION=true npx vitest run tests/integration/rfc-060-workflow.test.ts

# Run with watch mode (for development)
RUN_INTEGRATION=true npx vitest watch tests/integration/rfc-060-workflow.test.ts

# Run with verbose output
RUN_INTEGRATION=true npx vitest run tests/integration/rfc-060-workflow.test.ts --reporter=verbose
```

### Test Scripts Reference

From `package.json`:
- `npm test` - Run default test suite with `./run-tests.sh`
- `npm run test:memory` - Memory-safe mode (recommended for integration tests)
- `npm run test:watch` - Watch mode for development
- `npm run test:ci` - CI mode with memory safety and JSON output
- `npm run test:coverage` - Generate coverage reports
- `npm run test:full` - Full suite including e2e and live API tests

The `./run-tests.sh` script automatically:
- Handles memory constraints (8GB limit for Node.js)
- Loads `.env` file if present
- Detects CI environment and adjusts settings
- Provides colored output and error reporting

### Test Modes

- **Unit Mode**: Tests use mocks for all external dependencies (GitHub API, AI services)
- **Integration Mode**: Tests validate data flow between components (requires `RUN_INTEGRATION=true`)
- **Memory-Safe Mode**: Uses fork pool instead of threads to prevent OOM issues (via `--memory-safe`)
- **E2E Mode**: Full end-to-end testing with real services (requires `--e2e` flag)

## Nodegoat Environment Setup

### Repository Location

The `nodegoat-vulnerability-demo` repository should be cloned to:
```
/var/tmp/vibe-kanban/worktrees/nodegoat-vulnerability-demo
```

### Clone Nodegoat

```bash
cd /var/tmp/vibe-kanban/worktrees
git clone https://github.com/RSOLV-dev/nodegoat-vulnerability-demo.git
```

### Known Vulnerabilities in Nodegoat

Nodegoat contains intentional security vulnerabilities for testing:

1. **XSS (Cross-Site Scripting)**
   - Location: `app/views/tutorial/*.html`
   - Type: Unescaped template rendering

2. **SQL Injection**
   - Location: `app/data/*-dao.js`
   - Type: String concatenation in SQL queries

3. **Weak Cryptography**
   - Location: `app/routes/*.js`
   - Type: Use of deprecated crypto functions

4. **Path Traversal**
   - Location: `app/routes/contributions.js`
   - Type: Unsanitized file path handling

## Test Architecture

### Mock Strategy

Tests use Vitest mocking to isolate components and verify proper API usage:

```typescript
// Mock PhaseDataClient API
vi.mock('../../src/modes/phase-data-client/index.js', () => ({
  PhaseDataClient: vi.fn().mockImplementation(() => ({
    storePhaseResults: mockStorePhaseResults,
    retrievePhaseResults: mockRetrievePhaseResults
  }))
}));

// Mock TestRunner
vi.mock('../../src/utils/test-runner.js', () => ({
  TestRunner: vi.fn().mockImplementation(() => ({
    runTests: mockRunTests
  }))
}));

// Mock ExecutableTestGenerator
vi.mock('../../src/ai/executable-test-generator.js', () => ({
  ExecutableTestGenerator: vi.fn().mockImplementation(() => ({
    generateExecutableTests: mockGenerateExecutableTests
  }))
}));

// Mock GitHub API
vi.mock('../../src/github/api.js', () => ({
  getIssue: vi.fn(),
  createIssue: vi.fn(),
  addLabels: vi.fn()
}));

// Mock Scanner
vi.mock('../../src/scanner/index.js', () => ({
  ScanOrchestrator: vi.fn().mockImplementation(() => ({
    performScan: vi.fn()
  }))
}));
```

### Test Data Storage

Integration tests use PhaseDataClient API for data persistence:
- **Storage**: Via PhaseDataClient.storePhaseResults()
- **Retrieval**: Via PhaseDataClient.retrievePhaseResults()
- **No Direct File Access**: Tests do not use `fs` or local directories directly

### Validation Metadata Structure

```typescript
{
  issueNumber: 101,
  validationTimestamp: "2025-10-09T18:49:40.251Z",
  vulnerabilities: [
    {
      type: "XSS",
      file: "app/views/tutorial/a1.ejs",
      line: 42,
      confidence: "high"
    }
  ],
  testResults: {
    success: false,  // RED test - should fail initially
    testsRun: 1,
    testsFailed: 1,
    testsPassed: 0
  },
  validationMetadata: {
    patternMatchScore: 0.95,
    astValidationScore: 0.88,
    contextualScore: 0.92,
    dataFlowScore: 0.85
  },
  validated: true
}
```

## Troubleshooting

### Tests Not Found

**Error**: `No test files found`

**Solution**: Ensure you set `RUN_INTEGRATION=true` environment variable:
```bash
RUN_INTEGRATION=true npx vitest run tests/integration/rfc-060-workflow.test.ts
```

The integration tests are excluded by default in `vitest.config.ts` to prevent slow tests from running during regular development.

### Test Files Excluded (e2e pattern)

**Problem**: Files containing `e2e` in the name are excluded by vitest config

**Solution**: Test file is named `rfc-060-workflow.test.ts` (not `rfc-060-e2e-workflow.test.ts`)

### Mock Issues

**Problem**: Mocks not working correctly

**Solutions**:
1. Clear mock state: `vi.clearAllMocks()` in `beforeEach()`
2. Reset modules: `vi.resetModules()` in `afterEach()`
3. Check mock setup: Ensure `vi.hoisted()` for module-level mocks

### Directory Cleanup Errors

**Problem**: `.rsolv/phase-data` directory conflicts

**Solution**: Tests automatically clean up in `afterEach()`:
```typescript
try {
  await fs.rm(testDir, { recursive: true, force: true });
} catch (e) {
  // Ignore cleanup errors
}
```

## Success Criteria

All 6 integration tests passing:

- ✅ SCAN phase creates GitHub issues
- ✅ VALIDATE phase generates RED tests
- ✅ VALIDATE phase executes tests and stores results
- ✅ MITIGATE phase retrieves validation metadata
- ✅ MITIGATE phase includes test in prompt
- ✅ Full workflow completes successfully

## Next Steps (Phase 4.2 & 4.3)

- **Phase 4.2**: Language-specific testing (Python, JavaScript, TypeScript)
- **Phase 4.3**: Real nodegoat integration with actual AI fixes
- **Phase 4.4**: Trust score validation and metrics

## References

- **RFC-060**: Three-phase validation architecture
- **Test file**: `tests/integration/rfc-060-workflow.test.ts`
- **PhaseExecutor**: `src/modes/phase-executor/index.ts`
- **Validation types**: `src/validation/types.ts`
