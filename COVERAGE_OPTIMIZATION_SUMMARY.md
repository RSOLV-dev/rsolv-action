# CI Coverage Optimization Results

**Date**: 2025-11-01
**PR**: #57

## Problem
Extremely long runtimes in code coverage report generation on CI, with massive SQL query logs AND re-running the entire test suite.

## Root Causes Discovered

### 1. Debug-Level SQL Logging (INITIAL ISSUE)
`config/test.exs:34` had logger level set to `:debug`, causing all SQL queries to be logged during tests despite comment saying "Print only warnings and errors during test".

### 2. Coverage Job Re-Running All Tests (ACTUAL MAJOR ISSUE!)
The coverage job was using `mix coveralls.json --import-cover` which **re-runs the entire test suite** (4730 tests + 529 doctests = 171+ seconds) instead of just merging the .coverdata files.

**What we discovered:**
- Coverage report logs showed 24,417 lines of output
- Log showed "Running ExUnit with seed: 495830, max_cases: 4"
- Log showed "Finished in 171.5 seconds (44.0s async, 127.4s sync)"
- The `--no-start` flag only prevents app startup, NOT test execution
- `--import-cover` is meant to be used WITH tests running to merge additional coverage

## Solutions Applied

### 1. Fixed Logger Level
**File**: `config/test.exs:34-37`

Changed from `:debug` to `:info` to eliminate SQL query logging while maintaining coverage.

**Why :info instead of :warning?**
- Production code has 20+ `Logger.debug()` calls that need to execute for coverage
- At `:warning` level, these lines are compile-time optimized out → coverage drops to 59.8%
- Ecto SQL queries are logged at `:debug` level
- Using `:info` prevents SQL logging while allowing `Logger.debug()` calls to execute

### 2. Created Fast Coverage Merge Script
**File**: `scripts/merge_coverage.exs`

Custom Elixir script that uses the `:cover` module directly to merge .coverdata files WITHOUT running tests.

**What it does:**
1. Imports all .coverdata files using `:cover.import/1`
2. Analyzes merged coverage using `:cover.analyze/2`
3. Calculates total coverage percentage
4. Exports results for GitHub Actions

**What it DOESN'T do:**
- Compile application ❌
- Start database ❌
- Run any tests ❌
- Start the application ❌

### 3. Updated CI Workflow
**File**: `.github/workflows/elixir-ci.yml`

- Removed PostgreSQL service from coverage job (not needed)
- Disabled Coveralls upload (can re-enable if needed)
- Use custom merge script instead of `mix coveralls.json`

## Expected Results

**Before:**
- Coverage job: 4-5 minutes
- 24,417 lines of log output
- Re-runs all 4730 tests + 529 doctests
- Needs PostgreSQL service

**After:**
- Coverage job: Should be ~10-30 seconds
- Minimal log output (just merge progress)
- No tests run, just file merging
- No services needed

**Coverage maintained at 60.1%**

## What Didn't Work

1. **`:warning` logger level** - Dropped coverage to 59.8%
2. **Grep output filtering** - Broke percentage extraction
3. **`mix coveralls.json --no-start`** - Still runs all tests!

## Final Solution

Two changes:
1. **Logger level**: `:debug` → `:info` (prevents SQL logging, maintains coverage)
2. **Coverage merge**: Custom script using `:cover` module (no test re-execution)

## Notes for Merge
Remove this doc before merge - information captured in commit messages and code comments.
