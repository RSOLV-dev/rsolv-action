# ADR-023: Claude CLI Credential Passing in RetryableClaudeCodeCLI

**Status**: Implemented  
**Date**: 2025-09-02  
**Authors**: Infrastructure Team  
**Related**: ADR-001, ADR-011, RFC-012

## Context

During production testing, we discovered that vended credentials were not being properly passed to the Claude CLI when using the `RetryableClaudeCodeCLI` adapter. While the credential vending system (ADR-001) was successfully returning valid API keys, and the base `ClaudeCodeCLIAdapter` correctly handled environment variables, the `RetryableClaudeCodeCLI` had a critical bug.

### Problem Details

The `RetryableClaudeCodeCLI.getApiKey()` method was:
1. Successfully retrieving vended credentials from the credential manager
2. Returning the API key to be used in the `env` option of the spawned process
3. **NOT** setting `process.env.ANTHROPIC_API_KEY` globally

This caused Claude CLI to fail with "Invalid API key" errors because:
- The CLI reads from `process.env.ANTHROPIC_API_KEY` directly
- The `env` option in `spawn()` creates a copy of the environment, not modifying the parent process
- Subsequent CLI invocations didn't have access to the vended credentials

### Discovery Timeline

1. **Issue Reported**: Demo workflows failing with "Invalid API key" despite valid credential vending
2. **Initial Investigation**: Confirmed vended credentials were valid when tested directly
3. **Root Cause**: Found `RetryableClaudeCodeCLI` wasn't setting process.env
4. **Fix Applied**: Added `process.env.ANTHROPIC_API_KEY = apiKey` after credential retrieval

## Decision

We modified the `RetryableClaudeCodeCLI.generateSolution()` method to explicitly set the API key in the global process environment:

```typescript
// Before (broken):
const apiKey = this.getApiKey(isDev);
// ... later ...
const result = await this.executeWithRetry(prompt, {
  env: { ...process.env, ANTHROPIC_API_KEY: apiKey }
});

// After (fixed):
const apiKey = this.getApiKey(isDev);

// CRITICAL: Set the API key in process.env for Claude CLI to use
// This ensures the CLI can authenticate properly
process.env.ANTHROPIC_API_KEY = apiKey;

// ... continues with execution
```

### Why This Approach

1. **Global Environment Required**: Claude CLI reads directly from process.env
2. **Consistency**: Matches behavior of other adapters (claude-code.ts line 173)
3. **Simplicity**: Single point of truth for credential setting
4. **Reliability**: Ensures all child processes inherit the credential

## Consequences

### Positive

- **Immediate Fix**: Vended credentials now work correctly with Claude CLI
- **Consistent Behavior**: All Claude adapters now handle credentials identically
- **Production Ready**: Demo workflows execute successfully
- **Better Debugging**: Clear comment explains the critical nature of this line

### Trade-offs

- **Global State Modification**: Modifying process.env affects entire process
- **Potential Side Effects**: Other code might read ANTHROPIC_API_KEY
- **Cleanup Consideration**: API key remains in process.env after use

### Regression Protection

Added comprehensive tests to prevent recurrence:

1. **Unit Tests**: `claude-code-cli-retry-vended.test.ts`
   - Verifies process.env is set before CLI execution
   - Tests vended credential retrieval and usage
   - Ensures fallback to environment variables works

2. **Integration Tests**: `claude-code-cli-vended-credentials.test.ts`
   - End-to-end credential vending flow
   - Validates CLI receives proper authentication
   - Tests error scenarios

3. **Live Verification**: `test-vended-claude.sh`
   - Direct test of vended credentials with Claude CLI
   - Validates actual API calls succeed
   - Can be run as smoke test

## Implementation Evidence

**Fix Commit**: dd6040f - "fix: Set ANTHROPIC_API_KEY in process.env for Claude CLI vended credentials"

**Files Modified**:
- `src/ai/adapters/claude-code-cli-retry.ts` - Added process.env setting
- `src/ai/adapters/__tests__/claude-code-cli-retry-vended.test.ts` - New regression tests
- `src/ai/adapters/__tests__/claude-code-cli-vended-credentials.test.ts` - Additional coverage

**Production Verification**:
- ✅ GitHub Action workflow #17413996710 completed successfully
- ✅ Vended credentials working in production
- ✅ Demo rehearsal scripts functioning

## Lessons Learned

1. **Environment Variable Scope**: Child process `env` options don't affect parent process.env
2. **CLI Tools Assumptions**: Many CLI tools expect credentials in global environment
3. **Testing Coverage**: Need tests that specifically verify credential passing mechanisms
4. **Consistency Matters**: All adapters should handle credentials identically

## Future Considerations

1. **Credential Cleanup**: Consider clearing ANTHROPIC_API_KEY after use
2. **Scoped Credentials**: Investigate passing credentials without global state
3. **CLI Wrapper**: Create wrapper that handles credential injection
4. **Monitoring**: Add telemetry for credential vending success rates

## Related Documentation

- ADR-001: Credential Vending Architecture
- ADR-011: Claude Code SDK Integration  
- RFC-012: Secure Credential Vending System
- Test Suite: `src/ai/adapters/__tests__/*vended*.test.ts`