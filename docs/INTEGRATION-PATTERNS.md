# Common Integration Patterns and Edge Cases

**Purpose**: Document common patterns, edge cases, and best practices for RSOLV test integration.

**Audience**: Developers, DevOps engineers, and platform operators integrating RSOLV into their workflows.

**Last Updated**: 2025-10-15

---

## Table of Contents

1. [Framework-Specific Patterns](#framework-specific-patterns)
2. [Directory Structure Patterns](#directory-structure-patterns)
3. [Test File Naming Conventions](#test-file-naming-conventions)
4. [Edge Cases and Solutions](#edge-cases-and-solutions)
5. [Multi-Language Projects](#multi-language-projects)
6. [Monorepo Patterns](#monorepo-patterns)
7. [Custom Test Frameworks](#custom-test-frameworks)
8. [Performance Optimization](#performance-optimization)

---

## Framework-Specific Patterns

### Ruby + RSpec

**Standard Pattern**:
```ruby
# spec/controllers/users_controller_spec.rb
RSpec.describe UsersController, type: :controller do
  describe '#create' do
    it 'validates user input' do
      # Existing test
    end

    # RSOLV integration point: after last 'it' block in describe
    it 'detects SQL injection in user lookup' do
      # RSOLV generated test
      # Tests for CVE-XXXX-YYYY: SQL injection via username parameter
      malicious_input = "admin' OR '1'='1"
      expect { User.find_by_username(malicious_input) }.to raise_error(SecurityError)
    end
  end
end
```

**Scoring Factors**:
- Path similarity: `app/controllers/users_controller.rb` → `spec/controllers/users_controller_spec.rb` (**high score**)
- Module bonus: Same module `UsersController` (+0.3)
- Directory bonus: Matching `controllers/` structure (+0.2)
- **Total**: 1.0 (base) + 0.3 + 0.2 = **1.5** (excellent match)

**AST Insertion Strategy**:
- Target: Inside relevant `describe` block, after last `it` block
- Fallback: End of outermost `describe` block
- Preserves: Indentation, block style (`do...end`), comments

**Edge Case: RSpec with `:focus` tags**:
```ruby
describe '#create' do
  it 'validates input', :focus do
    # Test with focus tag
  end

  # RSOLV inserts here (respects focus tag placement)
  it 'detects SQL injection' do
    # RSOLV test without :focus (doesn't interfere)
  end
end
```

---

### JavaScript/TypeScript + Vitest

**Standard Pattern**:
```typescript
// __tests__/services/userService.test.ts
import { describe, it, expect } from 'vitest';
import { UserService } from '@/services/userService';

describe('UserService', () => {
  describe('createUser', () => {
    it('should validate email format', () => {
      // Existing test
    });

    // RSOLV integration point: after last 'it' in describe
    it('should detect XSS in user profile', () => {
      // RSOLV generated test
      // Tests for CVE-XXXX-YYYY: XSS via profile bio field
      const maliciousInput = '<script>alert("XSS")</script>';
      const user = UserService.createUser({ bio: maliciousInput });
      expect(user.bio).not.toContain('<script>');
    });
  });
});
```

**Scoring Factors**:
- Path similarity: `src/services/userService.ts` → `__tests__/services/userService.test.ts` (**high score**)
- Module bonus: Same module `UserService` (+0.3)
- Directory bonus: Matching `services/` structure (+0.2)
- **Total**: 1.2 + 0.3 + 0.2 = **1.7** (excellent match)

**AST Insertion Strategy**:
- Target: Inside relevant `describe` block, after last `it`/`test` function
- Handles: Both `it()` and `test()` syntax
- Preserves: Arrow functions, async/await, TypeScript types

**Edge Case: Vitest with `.concurrent`**:
```typescript
describe('UserService', () => {
  it.concurrent('parallel test 1', async () => {
    // Concurrent test
  });

  // RSOLV inserts here (without .concurrent)
  it('should detect XSS', () => {
    // RSOLV test runs normally (not concurrent)
  });
});
```

---

### JavaScript + Jest

**Standard Pattern**:
```javascript
// __tests__/utils/sanitizer.test.js
describe('sanitizer', () => {
  describe('sanitizeHtml', () => {
    test('should remove script tags', () => {
      // Existing test
    });

    // RSOLV integration point: after last test
    test('should detect XSS via event handlers', () => {
      // RSOLV generated test
      // Tests for CVE-XXXX-YYYY: XSS via onerror attribute
      const maliciousInput = '<img src=x onerror="alert(1)">';
      const result = sanitizeHtml(maliciousInput);
      expect(result).not.toContain('onerror');
    });
  });
});
```

**Scoring Factors**: (Same as Vitest, Jest uses identical file structure)

**AST Insertion Strategy**:
- Target: Inside relevant `describe` block, after last `test`/`it` function
- Handles: Both `test()` and `it()` syntax (Jest supports both)
- Preserves: Jest-specific matchers (`.toMatchSnapshot()`, `.toThrow()`)

**Edge Case: Jest with `.each`**:
```javascript
describe('sanitizer', () => {
  test.each([
    ['<script>', ''],
    ['<img onerror=>', ''],
  ])('should sanitize %s to %s', (input, expected) => {
    // Parameterized test
  });

  // RSOLV inserts here (without .each)
  test('should detect XSS', () => {
    // RSOLV test runs normally
  });
});
```

---

### Python + pytest

**Standard Pattern**:
```python
# tests/services/test_user_service.py
import pytest
from app.services.user_service import UserService

class TestUserService:
    def test_validate_email(self):
        """Existing test"""
        pass

    # RSOLV integration point: end of class
    def test_detect_sql_injection_in_search(self):
        """Tests for CVE-XXXX-YYYY: SQL injection via search parameter"""
        malicious_input = "admin' OR '1'='1"
        with pytest.raises(ValueError):
            UserService.search_users(malicious_input)
```

**Scoring Factors**:
- Path similarity: `app/services/user_service.py` → `tests/services/test_user_service.py` (**high score**)
- Module bonus: Same module `UserService` (+0.3)
- Directory bonus: Matching `services/` structure (+0.2)
- **Total**: 0.7 + 0.3 + 0.2 = **1.2** (good match)

**AST Insertion Strategy**:
- Target: End of relevant `class Test*` block
- Preserves: Class structure, pytest fixtures, docstrings
- Handles: Both function-based and class-based tests

**Edge Case: pytest with fixtures**:
```python
class TestUserService:
    @pytest.fixture
    def user_service(self):
        return UserService()

    def test_validate_email(self, user_service):
        # Uses fixture
        pass

    # RSOLV inserts here (does NOT use fixture)
    def test_detect_sql_injection(self):
        # RSOLV test creates own instance
        service = UserService()
        # ... test logic
```

---

## Directory Structure Patterns

### Pattern 1: Mirror Source Directory

**Source**: `app/controllers/admin/users_controller.rb`
**Test**: `spec/controllers/admin/users_controller_spec.rb`

**Scoring**: 1.0 (base) + 0.3 (module) + 0.2 (directory) = **1.5** ✅ Excellent

### Pattern 2: Flat Test Directory

**Source**: `src/services/user/profile/update.ts`
**Test**: `__tests__/update.test.ts` (no subdirectories)

**Scoring**: 0.4 (low path similarity) + 0.3 (module match if filename matches) = **0.7** ⚠️ Acceptable

**Recommendation**: Create subdirectories in `__tests__/` to mirror source structure:
```bash
mkdir -p __tests__/services/user/profile
# Better scoring: 1.0 + 0.3 + 0.2 = 1.5
```

### Pattern 3: Feature-Based Test Organization

**Source**: `src/features/checkout/payment.ts`
**Test**: `tests/integration/checkout/payment.integration.test.ts`

**Scoring**: 0.8 (good path similarity) + 0.3 (module) + 0.2 (directory) = **1.3** ✅ Good

**Note**: Backend ignores "integration" / "unit" subdirectories when calculating directory bonus.

### Pattern 4: Co-located Tests

**Source**: `src/components/Button/Button.tsx`
**Test**: `src/components/Button/Button.test.tsx` (same directory as source)

**Scoring**: 1.0 (perfect path match) + 0.3 (module) + 0.2 (directory) = **1.5** ✅ Excellent

**AST Integration**: Works perfectly, high confidence

---

## Test File Naming Conventions

### Supported Patterns

| Language | Pattern | Example | Score |
|----------|---------|---------|-------|
| Ruby | `*_spec.rb` | `user_controller_spec.rb` | ✅ 1.0 |
| JavaScript | `*.test.js` | `userService.test.js` | ✅ 1.0 |
| JavaScript | `*.spec.js` | `userService.spec.js` | ✅ 1.0 |
| TypeScript | `*.test.ts` | `userService.test.ts` | ✅ 1.0 |
| Python | `test_*.py` | `test_user_service.py` | ✅ 1.0 |
| Python | `*_test.py` | `user_service_test.py` | ✅ 1.0 |

### Edge Case: Mixed Naming

**Scenario**: Repository uses both `*.test.js` and `*.spec.js`

**Backend Behavior**: Recommends both patterns, ranks by path similarity

**Example**:
```json
{
  "recommendations": [
    {"path": "tests/userService.test.js", "score": 1.5},
    {"path": "tests/userService.spec.js", "score": 1.5}
  ]
}
```

**Resolution**: Action selects **first** recommendation (highest score, then lexicographic order)

### Edge Case: No Matching Files

**Scenario**: Source file `app/controllers/users_controller.rb`, but no `spec/` directory exists

**Backend Response**: Empty recommendations array `[]`

**Action Behavior**: Creates new file in `.rsolv/tests/validation.test.rb`

**Prevention**:
```bash
# Create test directory structure before running RSOLV
mkdir -p spec/controllers
touch spec/controllers/.gitkeep
```

---

## Edge Cases and Solutions

### Edge Case 1: File Has No Describe Blocks

**Scenario**: Test file is just top-level `it()` calls (no `describe`)

**Ruby Example**:
```ruby
# spec/simple_spec.rb
it 'does something' do
  expect(true).to be true
end

# RSOLV inserts here (end of file)
it 'detects vulnerability' do
  # RSOLV test
end
```

**AST Insertion Strategy**: Append to end of file

**Prevention**: None needed, this is valid test syntax

---

### Edge Case 2: Multiple Classes in One File

**Scenario**: Source file has multiple classes/modules

**Source**:
```python
# app/services.py
class UserService:
    pass

class AdminService:
    pass
```

**Test File**:
```python
# tests/test_services.py
class TestUserService:
    pass

# RSOLV inserts here - which class?
```

**Resolution**:
1. Backend returns highest-scoring file (may not be perfect)
2. AST insertion goes to **end of file** (not inside any class)
3. Operator should manually move test to correct class

**Future Enhancement**: Parse vulnerability metadata to identify target class

---

### Edge Case 3: Test File Uses Import Aliases

**Scenario**: Test imports module with different name

**Source**: `src/services/userService.ts`
**Test**:
```typescript
import { UserService as US } from '@/services/userService';

describe('UserService', () => {
  // RSOLV generates: const service = new UserService()
  // ERROR: UserService is not defined (should be US)
});
```

**Current Behavior**: Test may have import errors

**Workaround**: RSOLV test should use fully-qualified import:
```typescript
it('detects XSS', () => {
  import { UserService } from '@/services/userService';
  const service = new UserService();
  // ...
});
```

**Status**: Known limitation, future enhancement planned

---

### Edge Case 4: Test Framework Not Installed

**Scenario**: RSOLV tries to validate tests but framework is missing

**Symptoms**:
- `npm test` fails with `Error: Cannot find module 'vitest'`
- `bundle exec rspec` fails with `gem not found`
- `pytest` fails with `command not found`

**Resolution**:
1. **Check dependencies**:
```bash
# JavaScript
cat package.json | jq '.devDependencies'

# Ruby
bundle list | grep rspec

# Python
pip list | grep pytest
```

2. **Install framework**:
```bash
# JavaScript
npm install --save-dev vitest

# Ruby
bundle add rspec --group=development,test

# Python
pip install pytest
```

3. **Re-run validation**: RSOLV will retry test execution

**Prevention**: Add framework to repository before enabling RSOLV

---

### Edge Case 5: Tests Require Database Setup

**Scenario**: Generated test needs database fixtures/migrations

**Generated Test**:
```ruby
it 'detects SQL injection' do
  User.find_by_username("admin' OR '1'='1")
end
```

**Error**: `ActiveRecord::StatementInvalid: PG::ConnectionBad: connection failed`

**Resolution**:
1. **Update test to mock database**:
```ruby
it 'detects SQL injection' do
  allow(User).to receive(:find_by_username).and_return(nil)
  expect {
    User.find_by_username("admin' OR '1'='1")
  }.to raise_error(SecurityError)
end
```

2. **Or add database setup**:
```ruby
before do
  User.create!(username: 'admin', email: 'admin@example.com')
end

it 'detects SQL injection' do
  # Now database is populated
end
```

**Status**: RSOLV does not automatically add database setup (future enhancement)

**Workaround**: Manually edit generated tests to add setup

---

### Edge Case 6: Tests Require Authentication

**Scenario**: Generated test calls authenticated endpoint

**Generated Test**:
```typescript
it('detects XSS in user profile', async () => {
  const response = await fetch('/api/user/profile', {
    method: 'POST',
    body: JSON.stringify({ bio: '<script>alert(1)</script>' })
  });
  // ...
});
```

**Error**: `401 Unauthorized`

**Resolution**:
1. **Add authentication setup**:
```typescript
it('detects XSS in user profile', async () => {
  const authToken = await loginTestUser('test@example.com', 'password');
  const response = await fetch('/api/user/profile', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${authToken}` },
    body: JSON.stringify({ bio: '<script>alert(1)</script>' })
  });
  // ...
});
```

2. **Or mock authentication**:
```typescript
beforeEach(() => {
  vi.mock('@/lib/auth', () => ({
    isAuthenticated: () => true,
    getCurrentUser: () => ({ id: 1, role: 'user' })
  }));
});
```

**Status**: RSOLV does not automatically add auth setup (future enhancement)

---

## Multi-Language Projects

### Pattern: Polyglot Monorepo

**Structure**:
```
repo/
├── services/
│   ├── api/ (Ruby on Rails)
│   │   ├── app/
│   │   └── spec/
│   ├── frontend/ (TypeScript + React)
│   │   ├── src/
│   │   └── __tests__/
│   └── worker/ (Python)
│       ├── app/
│       └── tests/
└── .github/workflows/rsolv-autofix.yml
```

**Challenge**: RSOLV needs to detect language per vulnerability

**Solution**: Backend analyzes file extension:
- `.rb` → Ruby/RSpec
- `.js`/`.ts` → JavaScript/Vitest or Jest
- `.py` → Python/pytest

**Workflow Configuration**:
```yaml
- uses: RSOLV-dev/rsolv-action@v2
  with:
    api_key: ${{ secrets.RSOLV_API_KEY }}
    # No language override needed - auto-detects per file
```

**Test File Scoring**: Backend scores test files in **same language** only
- For `services/api/app/controllers/users_controller.rb`, only considers `*.rb` test files
- For `services/frontend/src/components/Button.tsx`, only considers `*.test.ts` files

---

## Monorepo Patterns

### Pattern: Multiple Services with Separate Test Suites

**Structure**:
```
monorepo/
├── services/
│   ├── user-service/
│   │   ├── src/
│   │   └── __tests__/
│   └── payment-service/
│       ├── src/
│       └── __tests__/
└── package.json (root)
```

**Test Commands**:
```json
{
  "scripts": {
    "test": "npm run test --workspaces",
    "test:user": "npm run test -w user-service",
    "test:payment": "npm run test -w payment-service"
  }
}
```

**RSOLV Integration**: Backend scores test files **globally** across workspace
- For `services/user-service/src/auth.ts`, considers:
  - `services/user-service/__tests__/auth.test.ts` (score: 1.5) ✅ Best
  - `services/payment-service/__tests__/auth.test.ts` (score: 0.6) ⚠️ Lower

**Best Practice**: Mirror source structure in each service's test directory

---

### Pattern: Shared Libraries in Monorepo

**Structure**:
```
monorepo/
├── packages/
│   ├── shared-utils/
│   │   ├── src/
│   │   └── __tests__/
│   └── validators/
│       ├── src/
│       └── __tests__/
└── apps/
    └── web/
        ├── src/ (imports from packages/)
        └── __tests__/
```

**Challenge**: Vulnerability in `packages/validators/src/input.ts`, but used in `apps/web/src/login.ts`

**RSOLV Behavior**:
1. Scan detects vulnerability in `packages/validators/src/input.ts`
2. Backend scores test files:
   - `packages/validators/__tests__/input.test.ts` (score: 1.5) ✅ Best
   - `apps/web/__tests__/login.test.ts` (score: 0.3) ❌ Too low
3. Test integrated into `packages/validators/__tests__/input.test.ts`

**Recommendation**: Always create test files next to source files in shared libraries

---

## Custom Test Frameworks

### Unsupported Framework: Minitest (Ruby)

**Current Status**: Minitest not supported (only RSpec)

**Workaround**:
1. **Add RSpec to project**:
```bash
bundle add rspec-rails --group=development,test
rails generate rspec:install
```

2. **Use both frameworks**:
```ruby
# test/models/user_test.rb (Minitest - existing)
class UserTest < ActiveSupport::TestCase
  test "validates email" do
    # ...
  end
end

# spec/models/user_spec.rb (RSpec - RSOLV generated)
RSpec.describe User do
  it 'detects SQL injection' do
    # RSOLV test
  end
end
```

3. **Run both**:
```bash
bundle exec rake test        # Minitest
bundle exec rspec           # RSpec
```

**Future Support**: Minitest support planned (RFC-060-AMENDMENT-002)

---

### Unsupported Framework: unittest (Python)

**Current Status**: unittest not supported (only pytest)

**Workaround**:
1. **Add pytest to project**:
```bash
pip install pytest pytest-cov
```

2. **Use both frameworks**:
```python
# tests/test_user.py (unittest - existing)
import unittest
class TestUser(unittest.TestCase):
    def test_validate_email(self):
        # ...

# tests/test_user_security.py (pytest - RSOLV generated)
import pytest
def test_detect_sql_injection():
    # RSOLV test
```

3. **Run both**:
```bash
python -m unittest discover  # unittest
pytest                       # pytest
```

**Future Support**: unittest support planned (RFC-060-AMENDMENT-002)

---

## Performance Optimization

### Optimization 1: Reduce Test File Candidates

**Problem**: Backend analyzing 100+ test files is slow

**Solution**: Limit scan to relevant directories

**Workflow Configuration**:
```yaml
- uses: RSOLV-dev/rsolv-action@v2
  with:
    api_key: ${{ secrets.RSOLV_API_KEY }}
    test_directories: 'spec/controllers,spec/models'  # Only search here
```

**Impact**: Analyze time reduced from 200ms → 50ms

---

### Optimization 2: Cache Test File Scan

**Problem**: Re-scanning test files on every validation

**Solution**: Cache test file list per repository

**Implementation**: (Future enhancement - not yet implemented)
```yaml
- uses: actions/cache@v3
  with:
    path: .rsolv/test-files-cache.json
    key: rsolv-test-files-${{ hashFiles('spec/**/*_spec.rb') }}
```

**Impact**: Eliminate redundant file system scans

---

### Optimization 3: Parallel Test Integration

**Problem**: Processing 10 issues sequentially takes 10x longer

**Solution**: Run VALIDATE phase in parallel

**Workflow Configuration**:
```yaml
jobs:
  find-issues:
    runs-on: ubuntu-latest
    outputs:
      issues: ${{ steps.list.outputs.issues }}
    steps:
      - id: list
        run: |
          ISSUES=$(gh issue list --label rsolv:automate --json number -q '.[].number')
          echo "issues=$ISSUES" >> $GITHUB_OUTPUT

  validate:
    needs: find-issues
    runs-on: ubuntu-latest
    strategy:
      matrix:
        issue: ${{ fromJSON(needs.find-issues.outputs.issues) }}
      max-parallel: 5  # Limit to 5 concurrent validations
    steps:
      - uses: RSOLV-dev/rsolv-action@v2
        with:
          mode: validate
          issue_number: ${{ matrix.issue }}
```

**Impact**: 10 issues processed in ~2 minutes (vs 20 minutes sequential)

**Caveat**: Be mindful of GitHub API rate limits and backend API quotas

---

## Related Documents

- [RFC-060 Completion Report](../../RFCs/RFC-060-COMPLETION-REPORT.md)
- [ADR-031: AST Integration Architecture](../../ADRs/ADR-031-AST-TEST-INTEGRATION.md)
- [Validation Troubleshooting Guide](VALIDATION-TROUBLESHOOTING.md)
- [Not-Validated Runbook](NOT-VALIDATED-RUNBOOK.md) (coming soon)

---

## Version History

- **v1.0** (2025-10-15): Initial version covering RFC-060 v3.7.54 + Amendment 001
- **Next review**: 2025-11-01 (after 6-week monitoring period)
