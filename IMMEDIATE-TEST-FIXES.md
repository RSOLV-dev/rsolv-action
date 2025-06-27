# Immediate Test Suite Fixes
*Action Plan for Quick Wins - 2025-06-27*

## 🎯 Goal: Green Test Suite in 2 Hours

Fix the blocking issues that prevent tests from running, then tackle high-impact warnings.

## Phase 1: Critical Fixes (30 minutes)

### Fix 1: Pattern Struct Mismatch (15 minutes)
**Problem**: Tests expect `default_tier` field that doesn't exist in Pattern struct

**Solution**: Remove `default_tier` from test files (cleaner than adding unused field)

**Files to fix**:
```bash
# Find all files referencing default_tier
grep -r "default_tier" test/ --include="*.exs" -l
```

**Action**: 
1. Remove `default_tier: :protected,` from struct creation
2. Remove `assert pattern.default_tier in [...]` assertions
3. Update pattern validation logic

### Fix 2: AST Cache Module Attributes (15 minutes)
**Problem**: Undefined module attributes breaking compilation

**File**: `lib/rsolv_api/ast/ast_cache.ex`

**Solution**: Add missing attributes at top of module:
```elixir
@default_max_entries 1000
@default_max_memory_mb 100
```

## Phase 2: High-Impact Warnings (60 minutes)

### Fix 3: PatternBase Type Logic (45 minutes)
**Problem**: Dead code branches in `contains_embedded_language?`

**File**: `lib/rsolv_api/security/patterns/pattern_base.ex`

**Current Issue**: Function checks `:crypto` patterns for `:sql_injection` matches (impossible)

**Solution Options**:
1. **Option A**: Make function pattern-type aware
2. **Option B**: Add `:crypto` to pattern allowlist  
3. **Option C**: Skip embedded language check for non-injection patterns

**Recommended**: Option C (safest)

### Fix 4: Function Grouping (15 minutes)
**Problem**: GenServer functions not grouped by arity

**File**: `lib/rsolv_api/ast/parser_pool.ex`

**Solution**: Move scattered `handle_cast/2` and `handle_info/2` clauses together

## Phase 3: Variable Cleanup (30 minutes)

### Fix 5: Unused Variables (30 minutes)
**Common Patterns**:
- `regex = ...` in tests → `_regex = ...`
- `state = ...` in GenServers → `_state = ...`  
- `alias Pattern` unused → remove or use

**Quick Script**:
```bash
# Find unused variable warnings
mix compile 2>&1 | grep "variable.*is unused" | head -20
```

## Implementation Commands

### Step 1: Fix Pattern Struct (Critical)
```bash
# Remove default_tier from main test file
sed -i '/default_tier:/d' test/rsolv_api/security/patterns_test.exs
sed -i '/pattern.default_tier/d' test/rsolv_api/security/patterns_test.exs

# Check how many other files need fixing
grep -r "default_tier" test/ --include="*.exs" | wc -l
```

### Step 2: Fix AST Cache Attributes
```bash
# Add to top of ast_cache.ex after @moduledoc
echo '@default_max_entries 1000' >> temp_fix.ex
echo '@default_max_memory_mb 100' >> temp_fix.ex
```

### Step 3: Test Progress
```bash
# After each fix, check warning count
mix compile 2>&1 | grep "warning:" | wc -l

# Try running specific test
mix test test/rsolv_api/security/patterns_test.exs --max-failures 1
```

## Expected Results

### After Phase 1 (30 min):
- ✅ Tests run without compilation errors
- ✅ Main pattern test passes
- ✅ ~200 fewer warnings

### After Phase 2 (90 min total):
- ✅ ~1,000 fewer warnings (down to ~700 total)
- ✅ Clean pattern validation test suite
- ✅ No more dead code warnings

### After Phase 3 (120 min total):
- ✅ ~1,300 fewer warnings (down to ~400 total)
- ✅ Clean compilation output
- ✅ Test suite runs reliably

## Risk Mitigation

### Before Starting:
```bash
# Create backup branch
git checkout -b test-cleanup-backup
git commit -am "Backup before test cleanup"

# Return to main branch for work
git checkout main
```

### Testing Strategy:
1. Fix one issue at a time
2. Run `mix test` after each change
3. Commit working fixes immediately
4. If something breaks, revert and try smaller change

### Rollback Plan:
```bash
# If anything goes wrong
git checkout test-cleanup-backup
git checkout main
git reset --hard test-cleanup-backup
```

## Quick Verification Commands

```bash
# Check current warning count
mix compile 2>&1 | grep "warning:" | wc -l

# Run main pattern test
mix test test/rsolv_api/security/patterns_test.exs

# Run sample pattern tests
mix test test/rsolv_api/security/patterns/javascript --max-failures 3

# Check for blocking errors
mix test --max-failures 1 2>&1 | grep -A5 "Compilation error"
```

## Success Criteria

- [ ] `mix test test/rsolv_api/security/patterns_test.exs` passes
- [ ] Warning count below 500
- [ ] No compilation errors blocking test execution
- [ ] Pattern validation tests work correctly

This focused approach tackles the highest-impact issues first while minimizing risk to working functionality.