# CI Coverage Optimization Results

**Date**: 2025-11-01
**PR**: #57

## Problem
Extremely long runtimes in code coverage report generation on CI, with massive SQL query logs.

## Root Cause
`config/test.exs:34` had logger level set to `:debug`, causing all SQL queries to be logged during tests despite comment saying "Print only warnings and errors during test".

## Solution Applied

### Fixed Logger Level
**File**: `config/test.exs:34-36`

Changed from `:debug` to `:warning` to eliminate SQL query logging while keeping error/warning visibility.

```elixir
# Before:
config :logger, level: :debug

# After:
config :logger, level: :warning
```

**Impact**: Dramatically reduces test log volume by eliminating verbose SQL query output.

## Results

The logger level change is the primary optimization. Coverage job now runs efficiently with normal logging levels.

**What Didn't Work:**
- Attempted to remove PostgreSQL service from coverage job, but `--no-start` flag doesn't prevent compilation which still needs DB
- Attempted to filter coverage output with grep, but broke percentage extraction
- Reverted both of these changes

**Final State:**
- Logger level: `:warning` (KEY FIX)
- PostgreSQL service: Restored (needed for compilation)
- Output: Unfiltered (simple and working)

## Notes for Merge
Main win was fixing the contradictory debug logging. This doc can be removed before merge - the commit messages capture the journey.
