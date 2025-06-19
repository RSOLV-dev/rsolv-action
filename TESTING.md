# RSOLV-action Testing Guide

## 📋 Test Suite Overview

### Current Status (June 19, 2025)
- **Total Tests**: 356
- **Passing**: 202 (57%)
- **Failing**: 124 (35%) - mostly due to test interference
- **Skipped**: 30 (8%)

### Test Organization
```
src/
├── __tests__/           # Integration tests for main modules
├── ai/
│   └── __tests__/       # AI provider and adapter tests
├── security/
│   └── *.test.ts        # Security pattern tests
├── containers/
│   └── __tests__/       # Container abstraction tests
└── credentials/
    └── __tests__/       # Credential manager tests

tests/
├── integration/         # Cross-module integration tests
├── e2e/                # End-to-end tests
└── platforms/          # Platform adapter tests
```

## 🔧 Running Tests

### Basic Commands
```bash
# Run all tests
bun test

# Run specific test file
bun test src/ai/__tests__/analyzer.test.ts

# Run tests matching pattern
bun test --grep "should detect"

# Run tests in watch mode
bun test --watch
```

### Test Configuration
The test setup is configured in:
- `bunfig.toml` - Preloads `setup-tests.ts`
- `setup-tests.ts` - Global test setup and utilities
- `test/setup.ts` - Additional test helpers

## ⚠️ Known Issues

### 1. Test Interference
Many tests pass individually but fail when run together due to global state pollution:

```bash
# These pass individually
bun test src/ai/__tests__/analyzer-parsing.test.ts  # ✅ 9 pass
bun test src/credentials/__tests__/manager.test.ts   # ✅ 10 pass

# But fail in full suite due to interference
bun test  # ❌ 124 fail
```

### 2. Global Fetch Mock
The `setup-tests.ts` file previously mocked `fetch` globally, causing issues with tests that need real HTTP calls (like Pattern API E2E tests). This has been changed to opt-in mocking:

```typescript
// Tests that need fetch mocked should do:
import { testUtils } from '../setup-tests.js';

beforeEach(() => {
  testUtils.setupFetchMock();
});
```

### 3. Module Import Issues
Bun requires `.js` extensions for ES module imports:
```typescript
// ❌ Wrong
import { Something } from './module';

// ✅ Correct
import { Something } from './module.js';
```

### 4. Mock Module Syntax
When mocking modules, use the correct syntax:
```typescript
// Mock a module
mock.module('./path/to/module.js', () => ({
  exportedFunction: mock(() => 'mocked value')
}));

// Mock with proper logger structure
mock.module('../utils/logger.js', () => ({
  logger: {
    info: mock(() => {}),
    warn: mock(() => {}),
    error: mock(() => {}),
    debug: mock(() => {})
  }
}));
```

## 🧪 Testing Patterns

### Container Testing
We use a Docker abstraction layer for testability:

```typescript
// Real implementation
const docker = new DockerClient();

// Test implementation  
const docker = new MockDockerClient();
docker.setAvailable(true);
docker.setPullSucceeds(false);

// Use in tests
await setupContainer(config, docker);
```

### AI Provider Testing
AI providers can be tested with mocked responses:

```typescript
// Setup fetch mock for AI tests
testUtils.mockFetch({
  ok: true,
  status: 200,
  json: { 
    content: [{ text: 'AI response' }] 
  }
});
```

### Pattern API Testing
Pattern API tests should use the local pattern source or mock the API:

```typescript
// Use local patterns for testing
const patternSource = new LocalPatternSource();
const detector = new SecurityDetectorV2(patternSource);
```

## 🚀 Integration Testing Strategy: Local → Staging → Production

### 1. Local Testing with `act`

[nektos/act](https://github.com/nektos/act) runs GitHub Actions locally in Docker, providing a complete simulation of the GitHub Actions environment.

```bash
# Install act
brew install act

# Test the action locally against staging
./test-local.sh

# Test with specific issue
./test-local.sh 123

# Test with custom event payload
act issues -e test-payloads/issue-opened.json -s RSOLV_API_KEY="$RSOLV_STAGING_API_KEY"
```

### 2. Staging Workflow Testing

Test against real staging environment on GitHub:

```bash
# Trigger staging test workflow
gh workflow run staging-test.yml \
  -f api_url="https://api.rsolv-staging.com" \
  -f issue_number="123"
```

### 3. Production Deployment Process

```bash
# 1. Test locally with act
./test-local.sh

# 2. Push to staging branch
git checkout -b staging
git push origin staging

# 3. Test staging workflow
gh workflow run staging-test.yml

# 4. If all tests pass, create release
git tag v1.0.x
git push origin v1.0.x

# 5. Update marketplace listing
gh release create v1.0.x --notes "Release notes"
```

## 🔄 Environment Configuration

### Local Testing
- API URL: `http://localhost:4000` or `https://api.rsolv-staging.com`
- API Key: Use staging key or test key
- Issues: Create test issues with `rsolv:staging-test` label

### Staging
- API URL: `https://api.rsolv-staging.com`
- API Key: `RSOLV_STAGING_API_KEY`
- Branch: `staging` or `main`
- Label: `rsolv:staging-test`

### Production
- API URL: `https://api.rsolv.dev` (default)
- API Key: `RSOLV_API_KEY`
- Branch: Tagged releases (`v1.0.0`)
- Label: `rsolv:automate`

## 🐛 Debugging Tips

### Enable Debug Mode
```yaml
env:
  RSOLV_DEBUG: 'true'
  ACTIONS_STEP_DEBUG: 'true'
```

### Test Specific Scenarios
```bash
# Test error handling
act -s RSOLV_API_KEY="invalid-key" -W .github/workflows/rsolv-dogfood.yml

# Test with different Node versions
act --platform ubuntu-latest=node:18

# Test with specific event payload
act issues -e test-payloads/issue-opened.json
```

### Common Issues
1. **Docker architecture mismatch**: Use `--container-architecture linux/amd64`
2. **Missing secrets**: Set via `-s SECRET_NAME=value`
3. **Network issues**: Use `--network host` for local API testing

## 📊 Test Coverage Checklist

- [ ] Issue detection and filtering
- [ ] API authentication (valid/invalid keys)
- [ ] Staging API connectivity
- [ ] Production API fallback
- [ ] Error handling and retries
- [ ] PR creation workflow
- [ ] Multi-language support
- [ ] Security pattern detection
- [ ] Timeout handling
- [ ] Rate limiting

## 🚀 Benefits of Local Testing

1. **Faster iteration**: No need to push code to test
2. **Cost savings**: No GitHub Actions minutes consumed
3. **Better debugging**: Full local logs and breakpoints
4. **Staging isolation**: Test against staging without affecting production
5. **Reproducible tests**: Consistent environment across team

## 🔍 Debugging Test Failures

### Running Tests in Isolation
When tests fail in the full suite but pass individually:

```bash
# Run without global setup
mv bunfig.toml bunfig.toml.bak
bun test
mv bunfig.toml.bak bunfig.toml

# Or run specific test files together to find interference
bun test file1.test.ts file2.test.ts
```

### Common Test Failures

1. **"logger.debug is not a function"**
   - Check logger mock structure matches actual logger
   - Ensure mock.module uses correct path with .js extension

2. **"Unmocked fetch call to: ..."**
   - Test needs fetch mock but doesn't set it up
   - Add `testUtils.setupFetchMock()` in beforeEach

3. **"export 'X' not found"**
   - Missing .js extension in import
   - Check all imports in test file

4. **Claude Code CLI tests**
   - Requires `claude` CLI available in PATH (check with `which claude`)
   - Set `RUN_LIVE_TESTS=true` for integration tests
   - Most tests skip if no API key available

### Test Maintenance

When adding new tests:
1. Use `.js` extensions for all imports
2. Mock modules at the top of the file before imports
3. Consider if test needs fetch mocked (opt-in, not global)
4. Run test in isolation first, then with full suite
5. Document any special requirements in test comments