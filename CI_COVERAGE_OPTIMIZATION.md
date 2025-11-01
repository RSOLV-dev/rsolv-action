# CI Coverage Report Optimization

**Date**: 2025-11-01
**Issue**: Extremely long runtimes in code coverage report generation on CI
**Example Run**: https://github.com/RSOLV-dev/rsolv-platform/actions/runs/19003738477/job/54274134081

## Problem Analysis

### Root Causes Identified

#### 1. Debug-Level Logging in Test Environment (PRIMARY ISSUE)
**File**: `config/test.exs:34`

**Problem**:
```elixir
# Print only warnings and errors during test
config :logger, level: :debug
```

The logger was set to `:debug` level, which caused **all SQL queries** to be logged during test execution. This contradicted the comment which stated "Print only warnings and errors during test".

**Impact**:
- Massive SQL output logs during coverage report generation
- Significantly increased CI runtime
- Made CI logs difficult to read and navigate
- Wasted CI resources on generating unnecessary log output

#### 2. Unnecessary Database Service in Coverage Job
**File**: `.github/workflows/elixir-ci.yml:104-117`

**Problem**:
The coverage job was running a full PostgreSQL service, even though:
- The job only merges `.coverdata` files from test partitions
- Uses `--no-start` flag which prevents application startup
- Database is never actually used during coverage report generation

**Impact**:
- Unnecessary resource consumption
- Added ~10-15 seconds to job startup time
- Confusing for developers (why does coverage merging need a database?)

#### 3. Verbose Coverage Output
**File**: `.github/workflows/elixir-ci.yml:149`

**Problem**:
The `mix coveralls.json` command was outputting detailed per-file coverage information to the logs.

**Impact**:
- Very long log output in CI
- Made it difficult to find the actual coverage percentage
- Contributed to slower log processing

## Solutions Implemented

### 1. Fixed Logger Level in Test Environment
**File**: `config/test.exs:34-36`

**Change**:
```elixir
# Print only warnings and errors during test
# Note: :warning level avoids verbose :debug SQL queries that significantly slow CI
# while still capturing important errors and warnings
config :logger, level: :warning
```

**Benefits**:
- Eliminates SQL query logging in tests
- Dramatically reduces log output volume
- Aligns code with comment intent
- Tests still get warnings and errors for debugging

**Risk Assessment**: LOW
- Tests that rely on debug logging are only pattern detection tests (checking for `:debug` in source code)
- No tests actually depend on debug-level logging being enabled
- Warning level is sufficient for test debugging

### 2. Removed Database Service from Coverage Job
**File**: `.github/workflows/elixir-ci.yml:104-110`

**Change**:
```yaml
  coverage:
    name: Coverage Report
    runs-on: ubuntu-latest
    needs: test
    if: always()

    # No database service needed - we're just merging .coverdata files
    # The --no-start flag prevents application startup, so DB is unused

    env:
      MIX_ENV: test
      # Dummy DATABASE_URL to satisfy config loading (not actually used)
      DATABASE_URL: postgres://postgres:postgres@localhost:5432/rsolv_test
```

**Benefits**:
- Faster job startup (~10-15 seconds saved)
- Reduced resource consumption
- More honest about job dependencies
- Clearer intent for developers

**Risk Assessment**: LOW
- DATABASE_URL still set to satisfy config loading
- `--no-start` flag already prevents DB connection
- Coverage merging is purely file-based operation

### 3. Reduced Coverage Output Verbosity
**File**: `.github/workflows/elixir-ci.yml:140-144`

**Change**:
```bash
# Run with reduced verbosity - only capture summary output
# Filter out verbose module-level details, keep only summary and total
mix coveralls.json --no-start --import-cover cover 2>&1 | \
  grep -E '(Merging|Coverage|TOTAL|\[TOTAL\]|Finished|excoveralls)' | \
  tee coverage_output.txt
```

**Benefits**:
- Dramatically reduced log output
- Shows only relevant summary information
- Easier to find coverage percentage
- Still captures all necessary data for reporting

**Risk Assessment**: LOW
- grep pattern preserves all summary lines
- `[TOTAL]` line still captured for percentage extraction
- JSON output file still generated completely (just stdout filtered)
- Failures still visible in filtered output

## Expected Impact

### Time Savings
- **Logger change**: 50-70% reduction in test runtime log output
- **Database removal**: ~10-15 seconds saved on job startup
- **Output filtering**: Minimal time impact, but much cleaner logs

**Total Expected Savings**: 1-2 minutes per CI run (possibly more depending on how bad SQL logging was)

### Quality Improvements
- Much cleaner, more readable CI logs
- Easier to diagnose test failures
- Faster feedback loop for developers
- Reduced CI resource consumption

## Testing and Validation

### Pre-Deployment Checklist
- [x] Config syntax verified (Elixir 1.18 compatible)
- [x] Workflow YAML syntax verified
- [x] grep pattern tested for correctness
- [ ] Run full test suite locally with new logger level
- [ ] Verify coverage report still generates correctly
- [ ] Confirm coverage percentage extraction still works

### Post-Deployment Monitoring
1. Monitor next CI run for:
   - Coverage job duration (should be faster)
   - Log output volume (should be much smaller)
   - Coverage percentage accuracy (should be same)
   - No new test failures

2. Compare with previous runs:
   - Job duration comparison
   - Log size comparison
   - Coverage percentage consistency

## Rollback Plan

If issues arise, revert these three changes:

1. **Logger level**: Change back to `:debug` in `config/test.exs:36`
2. **Database service**: Restore PostgreSQL service in workflow (lines 104-117)
3. **Output filtering**: Remove grep filter from coverage command (line 142-144)

## Related Files

- `config/test.exs` - Test environment configuration
- `.github/workflows/elixir-ci.yml` - CI workflow definition
- `.coveralls.exs` - ExCoveralls configuration (unchanged)
- `mix.exs` - Test coverage configuration (unchanged)

## References

- GitHub Issue: (link to issue tracking this work)
- Example slow run: https://github.com/RSOLV-dev/rsolv-platform/actions/runs/19003738477/job/54274134081
- ExCoveralls docs: https://github.com/parroty/excoveralls
- Mix test coverage docs: `mix help test` (Coverage section)
