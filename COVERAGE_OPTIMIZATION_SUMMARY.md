# CI Coverage Optimization Results

**Date**: 2025-11-01
**PR**: #57

## Problem
Extremely long runtimes in code coverage report generation on CI, with massive SQL query logs.

## Root Cause
`config/test.exs:34` had logger level set to `:debug`, causing all SQL queries to be logged during tests despite comment saying "Print only warnings and errors during test".

## Solution Applied

### Fixed Logger Level
**File**: `config/test.exs:34-37`

Changed from `:debug` to `:info` to eliminate SQL query logging while maintaining coverage.

```elixir
# Before:
config :logger, level: :debug

# After:
config :logger, level: :info
```

**Why :info instead of :warning?**
- Production code has many `Logger.debug()` calls (20+ instances)
- At `:warning` level, these lines are not executed (compile-time optimization)
- This caused coverage to drop from 60.2% to 59.8%
- Ecto SQL queries are logged at `:debug` level
- Using `:info` prevents SQL logging while allowing `Logger.debug()` calls to execute and be covered

**Impact**: Eliminates verbose SQL query output while maintaining test coverage at 60.1%.

## Results

**Coverage Job Runtime**: ~4-5 minutes (down from extremely long runtimes)
**Coverage**: 60.1% (maintained)
**Status**: ✅ Passing

## What Didn't Work

- **Attempted**: Remove PostgreSQL service from coverage job
  - **Issue**: `--no-start` flag doesn't prevent compilation which needs DB
  - **Resolution**: Restored PostgreSQL service

- **Attempted**: Filter coverage output with grep to reduce log verbosity
  - **Issue**: Broke percentage extraction, empty COVERAGE_PERCENT
  - **Resolution**: Reverted to simple unfiltered output

- **Attempted**: Use `:warning` logger level
  - **Issue**: `Logger.debug()` calls not executed, coverage dropped to 59.8%
  - **Resolution**: Changed to `:info` level

## Final Solution

**Single Change**: Logger level from `:debug` to `:info`
- Prevents Ecto SQL query logging (the main issue)
- Maintains coverage of `Logger.debug()` calls in production code
- Simple, effective, no other changes needed

## Notes for Merge
Remove this doc before merge - the commit messages and code comments capture everything needed.
