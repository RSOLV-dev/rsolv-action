# Skipped Tests Analysis

## Summary
We have **17 test suites** that are skipped or conditionally skipped across the codebase.

## Categories of Skipped Tests

### 1. **Live API Tests** (Require Real Credentials/Services)

#### Claude Code Live Tests
- **File**: `src/ai/__tests__/claude-code-live.test.ts`
- **Condition**: `CLAUDE_CODE_LIVE_TEST=true` 
- **Why Skipped**: Requires Claude Code CLI installed and real API calls
- **What it Tests**: Real Claude Code solution generation

#### LLM Adapter Live Tests  
- **File**: `src/ai/__tests__/llm-adapters-live.test.ts`
- **Condition**: `LIVE_LLM_TESTS=true` + provider flags
- **Why Skipped**: Makes real API calls to Anthropic, OpenAI, Ollama
- **What it Tests**: Real LLM provider responses and comparison

#### Vended Credential E2E Tests
- **File**: `src/ai/__tests__/vended-credential-e2e.test.ts`
- **Condition**: `VENDED_CREDENTIAL_E2E_TEST=true` + `RSOLV_API_KEY`
- **Why Skipped**: Requires real RSOLV API key for credential vending
- **What it Tests**: End-to-end credential exchange and LLM calls

### 2. **Integration Tests** (External Dependencies)

#### Jira Integration
- **File**: `tests/platforms/jira/jira-integration.test.ts`
- **Status**: Always skipped (`describe.skip`)
- **Why Skipped**: Requires real Jira instance/credentials
- **What it Tests**: Jira API integration for issue management

#### Claude Code Integration
- **File**: `src/ai/__tests__/claude-code-integration.test.ts`
- **Condition**: `REAL_CLAUDE_CODE_API=true`
- **Why Skipped**: Toggle between mocked and real API tests
- **What it Tests**: Claude Code integration with context gathering

### 3. **Demo/Example Tests**

#### Security Demo Environment
- **File**: `src/__tests__/security-demo.test.ts`
- **Status**: Always skipped (`describe.skip`)
- **Why Skipped**: Demo/example code not for regular test runs
- **What it Tests**: Security detection demo scenarios

### 4. **Full E2E Tests**

#### Demo E2E Flow
- **File**: `tests/e2e/full-demo-flow.test.ts`
- **Condition**: Requires `GITHUB_TOKEN`, `RSOLV_API_KEY`
- **Why Skipped**: Needs real GitHub repo and credentials
- **What it Tests**: Complete workflow from issue to PR

## Enable Test Commands

### Essential Live Tests
```bash
# Test vended credentials with real LLM
VENDED_CREDENTIAL_E2E_TEST=true \
RSOLV_API_KEY=your_key \
bun test src/ai/__tests__/vended-credential-e2e.test.ts

# Test all LLM providers
LIVE_LLM_TESTS=true \
TEST_ANTHROPIC=true \
TEST_OPENAI=true \
ANTHROPIC_API_KEY=your_key \
OPENAI_API_KEY=your_key \
bun test src/ai/__tests__/llm-adapters-live.test.ts

# Test Claude Code CLI
CLAUDE_CODE_LIVE_TEST=true \
CLAUDE_CODE_AVAILABLE=true \
bun test src/ai/__tests__/claude-code-live.test.ts
```

### Full E2E Test
```bash
# Complete demo flow
GITHUB_TOKEN=your_token \
RSOLV_API_KEY=your_key \
FORCE_REAL_AI=true \
bun test tests/e2e/full-demo-flow.test.ts
```

## Recommendations

### 1. **CI/CD Integration**
- Create test API keys with limited scope for CI
- Run subset of live tests nightly
- Monitor API costs

### 2. **Local Development**
- Provide `.env.test.example` with required variables
- Document which tests developers should run locally
- Create mock mode for expensive operations

### 3. **Test Organization**
- Move all live/E2E tests to dedicated directory
- Clear naming convention: `*.live.test.ts`, `*.e2e.test.ts`
- Separate test commands in package.json

### 4. **Coverage Gaps**
- Jira integration has no active tests (always skipped)
- Consider creating mock Jira server for testing
- Add more provider-specific tests

## Test Health Status

| Category | Total | Active | Skipped | Health |
|----------|-------|--------|---------|---------|
| Unit Tests | ~200 | ~200 | 0 | ✅ Good |
| Integration | ~40 | ~35 | 5 | ⚠️ OK |
| Live API | 15 | 0 | 15 | ❌ All Skipped |
| E2E | 2 | 0 | 2 | ❌ All Skipped |

**Note**: Live/E2E tests are appropriately skipped for normal test runs but should be run periodically with real credentials.