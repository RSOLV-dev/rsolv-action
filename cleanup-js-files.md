# JavaScript Test Files Cleanup Plan

## Files to Remove

### Root Directory Standalone Tests
These are redundant manual test scripts that have been superseded by proper TypeScript tests:

1. **fix-claude-code-adapter.js** - Manual fix script, no longer needed
2. **live-claude-code-test.js** - Manual integration test, covered by TS tests
3. **live-test.js** - Generic live test, functionality in TS tests
4. **simple-claude-test.js** - Simple manual test, covered by TS tests
5. **standalone-test.js** - Standalone test runner, not needed

### Tests Directory
Old JavaScript tests that have TypeScript equivalents:

6. **tests/test-claude-code.js** - Covered by src/ai/adapters/__tests__/claude-code.test.ts
7. **tests/test-claude.js** - Covered by src/ai/__tests__/claude-code.test.ts
8. **tests/test-client-claude-code.js** - Covered by src/ai/__tests__/client-claude-code.test.ts

### E2E Tests (Evaluate First)
9. **e2e-tests/claude-code-real-repo.js** - Check if this has unique value

### Files to Keep
- **claude-code-config.example.js** - Configuration example, might be useful
- **test-fixtures/claude-code/*.js** - Test fixture files used by TypeScript tests

## Verification Steps

Before removing each file:
1. Verify no unique test cases exist that aren't covered by TS tests
2. Check if any scripts are referenced in package.json
3. Ensure no documentation references these files

## Commands to Execute

```bash
# First, backup the files
mkdir -p archived/js-test-files
cp *.js tests/*.js e2e-tests/*.js archived/js-test-files/

# Remove the files
rm -f fix-claude-code-adapter.js
rm -f live-claude-code-test.js
rm -f live-test.js
rm -f simple-claude-test.js
rm -f standalone-test.js
rm -f tests/test-claude-code.js
rm -f tests/test-claude.js
rm -f tests/test-client-claude-code.js
```