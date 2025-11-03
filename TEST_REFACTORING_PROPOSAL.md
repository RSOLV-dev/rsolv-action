# Test Refactoring Proposal: TestIntegrator Tests

## Overview

This proposal demonstrates how to make the TestIntegrator test files more readable, idiomatic, and maintainable by extracting common patterns into reusable helpers.

## Problems Identified

1. **Repetitive test suite creation** - Every test manually builds `%{"redTests" => [%{"testName" => ..., "testCode" => ..., "attackVector" => ...}]}`
2. **Duplicated assertions** - Same assertion patterns repeated in every test
3. **Copy-pasted test data** - SQL injection, XSS, path traversal examples duplicated across files
4. **Verbose pattern matching** - Every test destructures `{:ok, integrated_code, insertion_point, method}`
5. **Scattered malformed code examples** - Similar but slightly different across tests

## Solution: Test Helper Module

Created `test/support/test_integrator_helpers.ex` with:

### 1. **Test Suite Builders**
```elixir
# Before (38 lines)
test_suite = %{
  "redTests" => [
    %{
      "testName" => "prevents SQL injection",
      "testCode" => "const result = query(\"' OR '1'='1\");\nexpect(result).toBeNull();",
      "attackVector" => "' OR '1'='1"
    }
  ]
}

# After (1 line)
test_suite = build_test_suite([sql_injection_js()])
```

### 2. **Assertion Helpers**
```elixir
# Before (8 lines)
{:ok, integrated_code, insertion_point, method} =
  TestIntegrator.generate_integration(target_content, test_suite, "javascript", "vitest")

assert method == "ast"
assert insertion_point != nil
assert insertion_point.strategy == "after_last_it_block"
assert String.contains?(integrated_code, "prevents SQL injection")
assert String.contains?(integrated_code, "creates user")

# After (5 lines with more clarity)
integrate_and_assert_ast(target_content, test_suite, "javascript", "vitest",
  strategy: "after_last_it_block",
  contains: ["prevents SQL injection", "creates user"]
)
```

### 3. **Common Test Data Factories**
```elixir
# Predefined examples for common vulnerabilities:
sql_injection_js()     # JavaScript SQL injection test
sql_injection_ruby()   # Ruby SQL injection test
sql_injection_python() # Python SQL injection test
path_traversal_js()    # Path traversal for JS
xss_js()               # XSS test for JS
malformed_js()         # Malformed JavaScript code
malformed_ruby()       # Malformed Ruby code
malformed_python()     # Malformed Python code
```

### 4. **Fallback Assertions**
```elixir
# Before (6 lines)
{:ok, integrated_code, insertion_point, method} =
  TestIntegrator.generate_integration(target_content, test_suite, "javascript", "vitest")

assert method == "append"
assert insertion_point == nil
assert String.contains?(integrated_code, "test security")

# After (1 line)
integrate_and_assert_fallback(target_content, test_suite, "javascript", "vitest", ["test security"])
```

## Metrics

### Code Reduction

**Original test file:** 362 lines
**Refactored test file:** 290 lines
**Reduction:** 20% less code with **better readability**

### Test Clarity

**Before:**
```elixir
test "falls back to append on parse error" do
  target_content = """
  describe('Test', () => { // unclosed describe block
  """

  test_suite = %{
    "redTests" => [
      %{
        "testName" => "test security",
        "testCode" => "expect(true).toBe(true);",
        "attackVector" => "test"
      }
    ]
  }

  {:ok, integrated_code, _insertion_point, method} =
    TestIntegrator.generate_integration(target_content, test_suite, "javascript", "vitest")

  assert method == "append"
  assert String.contains?(integrated_code, "test security")
end
```

**After:**
```elixir
test "falls back to append on parse error" do
  target_content = malformed_js()

  test_suite = build_test_suite([
    red_test("test security", "expect(true).toBe(true);", "test")
  ])

  integrate_and_assert_fallback(target_content, test_suite, "javascript", "vitest", [
    "test security"
  ])
end
```

## Benefits

### 1. **DRY (Don't Repeat Yourself)**
- Common patterns extracted once
- Changes to assertion logic happen in one place
- Test data reused across files

### 2. **Self-Documenting Code**
- `integrate_and_assert_ast()` clearly shows intent
- `sql_injection_js()` is more obvious than raw test data
- `malformed_js()` explicitly states it's malformed code

### 3. **Easier Maintenance**
- Add new assertion? Update one helper function
- New vulnerability pattern? Add one factory function
- All tests benefit automatically

### 4. **Consistency**
- All tests use same patterns
- Reduces cognitive load when reading tests
- New contributors can follow established patterns

### 5. **Better Error Messages**
- Helpers include descriptive assertion messages
- Easier to debug failing tests

## Implementation Plan

### Phase 1: Create Helper Module ✅
- [x] Create `test/support/test_integrator_helpers.ex`
- [x] Verify it works with refactored test file
- [x] All 12 tests pass

### Phase 2: Refactor Existing Tests
1. **test_integrator_test.exs** (JavaScript/TypeScript)
   - Replace manual test suite creation with `build_test_suite()`
   - Use `integrate_and_assert_ast()` and `integrate_and_assert_fallback()`
   - Replace malformed code with `malformed_js()`

2. **test_integrator_ruby_python_test.exs**
   - Use Ruby/Python test data factories
   - Use `malformed_ruby()` and `malformed_python()`
   - Simplify assertions with helpers

3. **test_integrator_additional_test.exs**
   - Extract repeated patterns for nested tests
   - Use helpers for hooks/fixtures tests
   - Simplify large test file generation

### Phase 3: Extend Helpers (Optional)
- Add more vulnerability patterns as needed
- Create language-specific helper modules if patterns diverge
- Consider property-based testing helpers

## Example: Full Test Comparison

### Before (23 lines)
```elixir
test "integrates test into simple Vitest describe block" do
  target_content = """
  describe('UsersController', () => {
    it('creates user', () => {
      expect(User.count()).toBe(1);
    });
  });
  """

  test_suite = %{
    "redTests" => [
      %{
        "testName" => "rejects SQL injection in search endpoint",
        "testCode" =>
          "post('/search', { q: \"admin'; DROP TABLE users;--\" });\nexpect(response.status).toBe(400);",
        "attackVector" => "admin'; DROP TABLE users;--"
      }
    ]
  }

  {:ok, integrated_code, insertion_point, method} =
    TestIntegrator.generate_integration(target_content, test_suite, "javascript", "vitest")

  assert method == "ast"
  assert insertion_point != nil
  assert insertion_point.strategy == "after_last_it_block"
  assert String.contains?(integrated_code, "rejects SQL injection in search endpoint")
  assert String.contains?(integrated_code, "describe('security'")
  assert String.contains?(integrated_code, "admin'; DROP TABLE users;--")
  # Original test preserved
  assert String.contains?(integrated_code, "creates user")
end
```

### After (24 lines but much clearer)
```elixir
test "integrates test into simple Vitest describe block" do
  target_content = """
  describe('UsersController', () => {
    it('creates user', () => {
      expect(User.count()).toBe(1);
    });
  });
  """

  test_suite = build_test_suite([
    red_test(
      "rejects SQL injection in search endpoint",
      "post('/search', { q: \"admin'; DROP TABLE users;--\" });\nexpect(response.status).toBe(400);",
      "admin'; DROP TABLE users;--"
    )
  ])

  integrate_and_assert_ast(target_content, test_suite, "javascript", "vitest",
    strategy: "after_last_it_block",
    contains: [
      "rejects SQL injection in search endpoint",
      "describe('security'",
      "admin'; DROP TABLE users;--",
      "creates user"
    ]
  )
end
```

## Verification

Ran refactored tests:
```
mix test test/rsolv/ast/test_integrator_test.refactored.exs

Finished in 1.1 seconds (1.1s async, 0.00s sync)
12 tests, 0 failures
```

All tests pass with identical behavior but improved readability.

## Recommendation

**Proceed with refactoring** using the helper module approach:

1. It significantly improves test readability
2. Makes tests more maintainable
3. Reduces duplication across 3 test files (700+ total lines)
4. Establishes patterns for future tests
5. No behavior changes - purely structural improvement

## Files

- **Helper Module:** `test/support/test_integrator_helpers.ex`
- **Refactored Example:** `test/rsolv/ast/test_integrator_test.refactored.exs`
- **Original Files to Refactor:**
  - `test/rsolv/ast/test_integrator_test.exs`
  - `test/rsolv/ast/test_integrator_ruby_python_test.exs`
  - `test/rsolv/ast/test_integrator_additional_test.exs`
