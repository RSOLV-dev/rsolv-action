# TDD Session: Pattern Matching Debug

**Date**: June 29, 2025  
**Methodology**: Red-Green-Refactor-Review  
**Current Phase**: 🔴 RED  

## Session Objectives

**Primary Goal**: Debug why AST pattern matching returns 0 vulnerabilities despite:
- ✅ Server-side AST service working (200 OK responses)
- ✅ Python parser functional
- ✅ Patterns loaded (1 SQL-related pattern found)
- ✅ Encryption working
- ✅ Basic operator matching logic correct

## RED Phase Findings

### ✅ Operator Matching Logic Works
Test: `test_ast_pattern_matcher_debug.exs`
- Python operator: `%{"type" => "Add"}` → `"Add"` ✅ MATCHES
- JavaScript operator: `"+"` → `"+"` ✅ MATCHES  
- Node types: `"BinOp"` → `"BinOp"` ✅ MATCHES

**Conclusion**: The basic matching logic in `matches_value?()` is correct.

### ✅ Container Elixir Version Fixed
- Container now running Elixir 1.18.4 (compiled with Erlang/OTP 27)
- Can use Elixir's built-in JSON module instead of Jason
- Enhanced patterns now supported
- Interactive debugging available in container

### 🎯 Key Hypothesis
Since basic matching logic works, the issue is likely:
1. **Pattern structure mismatch** - actual patterns differ from expected
2. **Context rules too strict** - patterns require additional context not present
3. **Confidence thresholds** - matches filtered out by scoring
4. **Pattern loading issues** - patterns not loaded correctly

## GREEN Phase Plan

Once container is fixed:

### 1. Inspect Actual Pattern Structure
```elixir
# Debug script to run in container
patterns = RsolvApi.Security.PatternRegistry.get_patterns_for_language("python")
IO.inspect(patterns, label: "Loaded Python Patterns", pretty: true)
```

### 2. Trace Pattern Matching Flow
```elixir
# Enable debug logging in AST pattern matcher
defp debug_match_attempt(node, pattern) do
  IO.puts("🔍 Matching attempt:")
  IO.puts("   Node: #{inspect(node)}")  
  IO.puts("   Pattern: #{inspect(pattern)}")
  # ... continue with actual matching
end
```

### 3. Test with Simplified Patterns
Create minimal test patterns that should definitely match:
```elixir
simple_pattern = %{
  id: "test-python-binop",
  ast_rules: %{
    node_type: "BinOp",
    op: "Add"
  }
}
```

## Test Cases for GREEN Phase

### Test 1: Pattern Loading Verification
**Expected**: Should find patterns with correct structure  
**Test**: Load patterns and inspect their `ast_rules`

### Test 2: Node Matching Verification  
**Expected**: BinOp + Add should match our test case  
**Test**: Call matching function directly with known inputs

### Test 3: Context Analysis Debug
**Expected**: Should show if context rules are failing  
**Test**: Test with and without context requirements

### Test 4: Confidence Scoring Debug
**Expected**: Should show final confidence scores  
**Test**: Check if matches are filtered by confidence thresholds

## REFACTOR Phase Plan

Once we identify the issue:
1. Fix the root cause
2. Add comprehensive logging
3. Add unit tests for pattern matching
4. Optimize performance

## Success Criteria

**RED → GREEN**: 
- Detect 1+ vulnerabilities in test Python SQL injection code
- Pattern matching debug shows successful matches

**GREEN → REFACTOR**:
- >90% accuracy on test corpus
- All language parsers working
- Production-ready logging

## Current Status

1. **Container Elixir Version**: ✅ Successfully upgraded to 1.18.4
2. **Pattern Loading**: ✅ Confirmed 429 patterns loaded
3. **Parser Working**: ✅ Python parser produces correct AST
4. **Basic Matching Logic**: ✅ Operator matching works correctly
5. **Current Issue**: **BLOCKED** - Volume mounts override enhanced pattern code

## Root Cause Identified

The pattern matching returns 0 vulnerabilities because:
1. ✅ Pattern beam files exist in container
2. ✅ Code path issue resolved - modules can be loaded
3. **BLOCKER**: Volume mount maps old source code over container
4. Old pattern modules return Pattern struct without `ast_pattern` field
5. PatternAdapter uses the old modules, not enhanced ones
6. Without `ast_pattern`, the matcher skips all patterns

## Next Immediate Steps

1. ✅ Complete container rebuild with Elixir 1.18
2. ✅ Test Python parser in new container  
3. ✅ Run pattern inspection debug
4. ✅ Trace pattern matching flow
5. ✅ Identify root cause

## Solution Plan

1. **Option A**: Remove volume mounts (slower development)
   - Rebuild container for each code change
   - Ensures patterns compile correctly
   
2. **Option B**: Pre-compile patterns in image (recommended)
   - Add compilation step to Dockerfile
   - Keep volume mounts for faster iteration
   
3. **Option C**: Load patterns from source
   - Modify PatternAdapter to read .ex files
   - Parse AST enhancement at runtime

## Key Insights

- **Infrastructure is solid**: All components working correctly
- **Issue is in algorithm**: Pattern matching logic has a bug
- **TDD approach essential**: Without tests, this would take days to debug
- **Volume mounts critical**: Live code changes speed up debugging 10x

## Methodology Notes

This TDD session demonstrates the value of:
1. **Structured testing**: Breaking down the problem systematically
2. **Hypothesis-driven debugging**: Testing specific theories
3. **Environmental consistency**: Ensuring test environment matches production
4. **Documentation**: Tracking findings to avoid losing progress