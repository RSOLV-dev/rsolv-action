# Test Pollution Analysis - RFC-037 Consolidation

## Current Status
- **Initial failures**: 336
- **After Ecto fix**: 312  
- **After clean build**: 234
- **All tests pass individually** ✓

## Key Findings

### 1. Ecto Repo Startup Issues (Fixed)
- Modified `ConnCase` to use `start_owner!` instead of `checkout`
- This fixed all web controller tests (237 tests passing)
- `DataCase` already had the fix applied

### 2. Build Artifacts Issue (Partially Fixed)
- Found corrupted `.mix_test_failures` file with binary garbage
- Clean build (`rm -rf _build/test`) reduced failures from 387 to 234

### 3. Test Pollution Pattern
**All failing tests pass when run individually**, indicating:
- Shared state between tests
- Test execution order dependencies
- Resource contention (ETS tables, GenServers, etc.)

### 4. Categories of Failing Tests
1. **Cache Tests** (VulnerabilityValidationCacheTest)
   - Cache invalidation tests
   - TTL tests
   - Batch request tests

2. **AST Analysis Tests** (AnalysisServiceTest)
   - File analysis tests
   - Pattern matching tests
   - Performance tracking tests

3. **Controller Tests** (PatternControllerTest, FixAttemptControllerTest)
   - API endpoint tests
   - Authentication tests
   - Data validation tests

## Root Causes

### 1. ETS Table Pollution
Multiple tests use shared ETS tables:
- `:validation_cache`
- `:ast_cache`
- `:pattern_cache`
- `:session_cache`

### 2. GenServer State Pollution
Services that maintain state across tests:
- `Rsolv.Security.PatternServer`
- `Rsolv.AST.SessionManager`
- `Rsolv.AST.ParserPool`
- `Rsolv.Cache.ValidationCache`

### 3. Module Redefinition Warnings
Test helper files being loaded multiple times:
```
warning: redefining module Rsolv.IntegrationCase
warning: redefining module RsolvWeb.ConnCase
warning: redefining module Rsolv.DataCase
```

## Next Steps

1. **Implement proper test isolation**:
   - Clear ETS tables between tests
   - Reset GenServer states
   - Use unique process names for async tests

2. **Fix module loading**:
   - Use `Code.ensure_loaded?` before requiring files
   - Consider using `Application.compile_env` for test helpers

3. **Add test setup/teardown hooks**:
   - Global setup to ensure clean state
   - Per-test cleanup of shared resources

4. **Consider test execution strategies**:
   - Run problematic tests with `async: false`
   - Group related tests to minimize state conflicts
   - Use separate test commands for different test categories

## Date: 2025-07-05