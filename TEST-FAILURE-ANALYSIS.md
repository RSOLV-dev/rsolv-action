# Test Failure Analysis

## Current Status (2025-10-06)

After rollback to commit 617426e and API key fix:

**Test Results**:
- Total: 1012 tests
- Passed: 899 tests (88.83%)
- Failed: 54 tests  
- Skipped: 54 tests

**API Key Fixed**:
- Created new test API key: `cnNvbHZfdGVzdF9BpbZ_s4Y2nCA7aRRgH4LDdT86`
- Pattern API authentication now working
- Reduced failures from 73→54 tests

**Failing Test Suites** (22 total):
1. src/ai/__tests__/git-based-processor-test-mode.test.ts
2. src/ai/adapters/__tests__/claude-cli-mitigation.test.ts
3. src/ai/adapters/__tests__/claude-code-git-data-flow.test.ts
4. src/security/pattern-api-client.test.ts
5. src/ai/__tests__/git-status-rsolv-ignore.test.ts
6. src/ai/__tests__/token-utils.test.ts
7. src/modes/__tests__/phase-decomposition-simple.test.ts
8. src/modes/__tests__/vendor-filtering-all-phases.test.ts
9. src/ai/adapters/__tests__/claude-code-git-enhanced.test.ts
10. src/security/pattern-source.test.ts
11. test/regression/pattern-availability.test.ts
12. src/scanner/__tests__/issue-creator-max-issues.test.ts
13. src/ai/adapters/__tests__/claude-code-git-prompt.test.ts
14. src/ai/__tests__/git-based-processor-characterization.test.ts
15. src/modes/__tests__/validation-test-commit.test.ts
16. src/scanner/__tests__/ast-validator-mocked.test.ts
17. src/__tests__/ai/anthropic-vending.test.ts
18. src/ai/__tests__/ai-test-generator-maxtokens.test.ts
19. src/config/__tests__/model-config.test.ts
20. src/modes/__tests__/phase-executor.test.ts
21. src/ai/adapters/__tests__/claude-code-cli-retry-vended.test.ts
22. src/ai/adapters/__tests__/claude-code-git.test.ts

**Test Failure Categories**:
1. Git-based processor tests (test mode, characterization, data flow)
2. Claude Code CLI adapter tests (mitigation, retry, git integration)
3. Pattern API/source tests (remaining auth/format issues)
4. Phase executor/decomposition tests
5. AST validator mocked tests
6. Model config tests
7. Credential vending tests

**Next Actions**:
1. Export RSOLV_API_KEY in CI/test environment
2. Fix git-based processor test mode issues
3. Fix Claude Code CLI adapter test failures  
4. Fix remaining pattern API test issues
5. Fix phase executor test failures
6. Verify all tests green before RFC-060 work

