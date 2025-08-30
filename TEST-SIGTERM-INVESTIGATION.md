# SIGTERM Test Suite Investigation Summary

## Problem
The test suite receives SIGTERM after exactly 15 seconds when running `mix test`, causing tests to abort with ETS table errors.

## Investigation Process

### 1. Initial Hypothesis Testing
- **Environment timeout**: Tested `sleep 20` - completed successfully ✓
- **Elixir runtime timeout**: Tested plain Elixir script with 20s sleep - completed successfully ✓
- **Mix-specific issue**: Confirmed issue only occurs with `mix test` ✗

### 2. Key Discoveries

#### Working Scenarios:
- `mix test --trace` - Completes full suite in 32.1 seconds (sets timeout to infinity)
- `mix test test/specific_file.exs` - Individual test files work fine
- `mix test --timeout 60000` - Still fails at 15s (timeout parameter doesn't prevent SIGTERM)

#### Failing Scenarios:
- `mix test` - Receives SIGTERM at exactly 15 seconds
- Full test suite without --trace flag

### 3. Research Findings

From Kagi/community research:
- Default ExUnit timeout is 30 seconds (not 15)
- `--trace` sets timeout to infinity, which explains why it works
- SIGTERM logging format suggests application-level handling

### 4. Root Cause Analysis

The 15-second SIGTERM appears to be coming from:
1. **Not from**: Shell, Bash tool, system ulimits, Elixir runtime
2. **Likely from**: Unknown process monitor or test runner configuration
3. **Specific trigger**: Only when running full test suite without trace mode

## Solution/Workaround

### Immediate Workaround
Use one of these approaches to run tests:
```bash
# Option 1: Use --trace flag (slower but complete)
mix test --trace

# Option 2: Run tests in smaller batches
mix test test/rsolv
mix test test/rsolv_web

# Option 3: Use custom test script
```

### Permanent Fix Options
1. Add timeout configuration to test_helper.exs:
   ```elixir
   ExUnit.start(timeout: 60_000, exclude: exclude_tags)
   ```

2. Create a mix alias in mix.exs:
   ```elixir
   defp aliases do
     [
       "test.full": ["test --trace"],
       # ... other aliases
     ]
   end
   ```

3. Investigate further to find the source of the 15-second limit

## Current Test Suite Status

With --trace flag:
- **Total tests**: 3,650 (507 doctests + 3,143 tests)
- **Failures**: 6
- **Excluded**: 83
- **Skipped**: 36
- **Runtime**: 32.1 seconds

## SOLVED: Root Cause Identified

The 15-second SIGTERM was **NOT** coming from Elixir/Mix/ExUnit at all!

After extensive investigation, we discovered:
- When run natively with `mix test`, the suite completes successfully in ~70 seconds
- The SIGTERM only occurred when tests were run through certain execution contexts
- The issue was environmental, not a bug in the codebase or Elixir

### Test Results (Native Execution)
- **Total runtime**: ~70 seconds
- **Total tests**: 4,474 (529 doctests + 3,945 tests)  
- **Failures**: 36 (down from initial 64!)
- **No SIGTERM or timeout issues**

## Next Steps
1. Use `mix test --trace` for full test runs (confirmed workaround)
2. Consider filing an issue with elixir-lang/elixir if this persists
3. Fix the 6 remaining test failures (mostly SafePatternDetector logic issues)

## Technical Notes
- The SIGTERM happens exactly at 15 seconds, very consistently
- It's not related to individual test timeouts but overall suite runtime
- The error cascade (ETS table errors) happens because ExUnit.Server is terminated mid-run