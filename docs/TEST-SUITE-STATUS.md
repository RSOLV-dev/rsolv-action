# RSOLV-action Test Suite Status

*Last Updated: 2026-01-29*

## Overall Status: ✅ Operational

The test suite has been successfully migrated from Bun to Vitest with significant improvements in type safety and test reliability.

## Test Coverage Summary

### Core Modules (100% Passing)
- **src/modes/**: All tests passing (including phase2-regression tests for test sanitization)
- **src/ai/adapters/**: All adapter tests passing
- **src/scanner/**: All scanner tests passing

### Known Issues
1. **Dynamic Import Limitation**: `processIssues` in phase-executor cannot be properly mocked (documented workaround in place)
2. **Memory Constraints**: Use `npm run test:memory` for memory-safe execution with semi-parallel sharding (8 shards, 2 batches of 4)
3. **Some Integration Tests Skipped**: Server-side AST integration tests are skipped (require platform connection)

## Key Improvements Made

### Type Safety
- Replaced numerous `any` types with proper TypeScript interfaces
- Created comprehensive type definitions for phase data structures
- Improved IDE support and compile-time error detection

### Test Infrastructure
- Proper Vitest mock hoisting with `vi.hoisted()`
- GitHub API mocking using nock library
- Fixed test isolation issues between tests
- Proper environment variable handling

### Test Reliability
- Fixed phase data storage and retrieval
- Resolved mock pollution between tests
- Corrected test expectations to match actual implementation
- Added proper error handling in tests

## Running Tests

```bash
# Memory-safe full suite (recommended)
npm run test:memory

# Run a specific test file
npx vitest run src/modes/__tests__/phase2-regression.test.ts

# Run with coverage
npx vitest run --coverage

# Run a specific test by name
npx vitest run -t "should execute all three phases"
```

**Important**: Do NOT use `npm test` for the full suite — it causes OOM errors. Use `npm run test:memory` which runs 8 shards in 2 batches of 4 parallel workers with 4GB heap limit.

## Maintenance Notes

1. **Always run TypeScript validation**: `npx tsc --noEmit` after changes
2. **Mock Management**: Use `vi.clearAllMocks()` in `beforeEach`
3. **Test Isolation**: Restore modified mocks after tests
4. **Environment Variables**: Set `GITHUB_TOKEN` for GitHub API tests

## Test Sanitization (v3.8.25+)

The VALIDATE phase generates test code via `AdaptiveTestGenerator`. AI-generated `testCode` can contain various framework structures that need handling:

| Pattern | Detection | Fix |
|---------|-----------|-----|
| `test()` inside `it()` | `sanitizeTestStructure()` | Strip `test()` wrapper, keep body |
| `describe()/it()` inside `it()` | `sanitizeTestStructure()` | Strip nested wrappers, keep body |
| `testCode` with complete `describe()` | `hasFrameworkStructure()` | Use directly, skip wrapping |

Regression tests: `src/modes/__tests__/phase2-regression.test.ts`

## Future Improvements

1. Refactor dynamic imports to static imports for better testability
2. Continue gradual migration from remaining `any` types
3. Add more comprehensive integration tests