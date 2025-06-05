# E2E Test Coverage Analysis

## Current State

### 1. **Vended Credential + LLM API Test** ❌ → ✅ (Just Created)
**File**: `src/ai/__tests__/vended-credential-e2e.test.ts`
- Tests real credential exchange with RSOLV API
- Makes actual LLM API calls with vended credentials
- Verifies we get valid responses
- **Run with**: `VENDED_CREDENTIAL_E2E_TEST=true RSOLV_API_KEY=xxx bun test vended-credential-e2e.test.ts`

### 2. **Claude Code + Vended Credentials + Issue Solution** ⚠️ (Partial)
**Current Limitation**: Claude Code CLI uses its own authentication mechanism, not vended credentials.

**What we have**:
- `src/ai/__tests__/claude-code-live.test.ts` - Tests Claude Code but with direct auth
- `tests/e2e/full-demo-flow.test.ts` - Full workflow but requires real credentials

**What's missing**:
- Claude Code doesn't currently support vended credentials (uses CLI auth)
- Would need to modify Claude Code adapter to use vended API keys

### 3. **Live LLM Tests** ✅ (Exists but Disabled)
**File**: `src/ai/__tests__/llm-adapters-live.test.ts`
- Tests multiple providers (Anthropic, OpenAI, Ollama)
- Includes vended credential test for Anthropic
- **Run with**: `LIVE_LLM_TESTS=true TEST_ANTHROPIC=true bun test llm-adapters-live.test.ts`

### 4. **Full E2E Demo Flow** ✅ (Exists but Requires Setup)
**File**: `tests/e2e/full-demo-flow.test.ts`
- Complete workflow from issue to PR
- Uses real GitHub repo
- Includes security analysis
- **Requires**: GitHub token, RSOLV API key, demo repository

## Test Execution Commands

### Quick E2E Validation (Vended Credentials + LLM)
```bash
# Test vended credential exchange and LLM calls
VENDED_CREDENTIAL_E2E_TEST=true \
RSOLV_API_KEY=your_rsolv_key \
bun test src/ai/__tests__/vended-credential-e2e.test.ts
```

### Full Live LLM Tests
```bash
# Test all LLM providers with real API calls
LIVE_LLM_TESTS=true \
TEST_ANTHROPIC=true \
RSOLV_API_KEY=your_rsolv_key \
bun test src/ai/__tests__/llm-adapters-live.test.ts
```

### Claude Code Live Tests
```bash
# Test Claude Code CLI integration (separate auth)
CLAUDE_CODE_LIVE_TEST=true \
CLAUDE_CODE_AVAILABLE=true \
bun test src/ai/__tests__/claude-code-live.test.ts
```

### Full Demo E2E
```bash
# Complete end-to-end workflow
GITHUB_TOKEN=your_token \
RSOLV_API_KEY=your_key \
FORCE_REAL_AI=true \
bun test tests/e2e/full-demo-flow.test.ts
```

## Gap Analysis

### ✅ What We Have:
1. Unit tests with proper mocking boundaries
2. Integration tests for vended credentials
3. Live API tests (disabled by default)
4. E2E test for vended credentials + LLM
5. Full workflow E2E test

### ⚠️ What's Limited:
1. Claude Code doesn't use vended credentials (uses CLI auth)
2. E2E tests require real credentials and aren't run in CI
3. No automated way to test the full vended → Claude Code flow

### 📋 Recommendations:
1. Run the vended credential E2E test regularly to ensure the flow works
2. Consider adding a mock mode for Claude Code that can use vended credentials
3. Set up a test environment with limited-scope API keys for CI/CD
4. Add monitoring for credential vending in production