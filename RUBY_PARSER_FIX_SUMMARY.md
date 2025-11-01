# Ruby Parser Test Fix Summary

**Date:** 2025-11-01
**Task:** Fix Ruby parser dependency test failures
**Status:** ✅ **RESOLVED**

## Problem

Ruby parser integration tests were failing due to incorrect AST node type names in test assertions. The tests were written for the old `parser` gem format but the implementation uses Ruby Prism, which has different node type naming conventions.

**Error:**
```elixir
Assertion with >= failed
code:  assert length(lvasgn_nodes) >= 1
left:  0
right: 1
```

## Root Cause

The Ruby parser (`priv/parsers/ruby/parser.rb`) uses the **Prism** gem (Ruby's built-in AST parser) which has different node type names than the older `parser` gem:

- Prism uses node types like `local_variable_write_node`
- The parser strips the `_node` suffix for compatibility: `local_variable_write`
- Tests were looking for the old `parser` gem format: `lvasgn`

**From `priv/parsers/ruby/parser.rb:48`:**
```ruby
# Strip _node suffix from Prism types for compatibility
type_str = node.type.to_s.sub(/_node$/, '')
```

## Solution

Updated test assertions in `test/rsolv/ast/production_ruby_parser_test.exs` to use correct Prism node types:

**Before:**
```elixir
lvasgn_nodes = find_nodes(result.ast, "lvasgn")
assert length(lvasgn_nodes) >= 1
```

**After:**
```elixir
# Prism uses "local_variable_write" not "lvasgn" (old Parser gem format)
lvasgn_nodes = find_nodes(result.ast, "local_variable_write")
assert length(lvasgn_nodes) >= 1
```

## Test Results

### Before Fix
- **Status:** 1 failure out of 10 tests
- **Failing test:** `"returns metadata about parser and language version"`

### After Fix
- **Status:** ✅ **All tests passing**
- **Results:**
  - `production_ruby_parser_test.exs`: 10/10 tests passed ✅
  - `test_integrator_ruby_python_test.exs`: 18/18 tests passed ✅
  - `multi_language_parsing_test.exs`: 19/19 tests passed (2 skipped) ✅

## Files Modified

1. **test/rsolv/ast/production_ruby_parser_test.exs**
   - Updated line 184-188: Changed `"lvasgn"` to `"local_variable_write"`
   - Added clarifying comment about Prism vs Parser gem

2. **.github/workflows/elixir-ci.yml**
   - Updated line 77-79: Removed "Ruby parser dependencies" from known issues
   - Added note about fix in comments

## Verification Commands

```bash
# Run Ruby parser tests
mix test test/rsolv/ast/production_ruby_parser_test.exs --include integration

# Run Ruby/Python integrator tests
mix test test/rsolv/ast/test_integrator_ruby_python_test.exs --include integration

# Run multi-language tests
mix test test/rsolv/ast/multi_language_parsing_test.exs --include integration
```

## Technical Details

### Prism Node Type Mappings

Common Ruby AST node types in Prism (after `_node` suffix removal):

| Prism Type | Old Parser Gem | Description |
|-----------|----------------|-------------|
| `local_variable_write` | `lvasgn` | Local variable assignment |
| `def` | `def` | Method definition |
| `class` | `class` | Class definition |
| `module` | `module` | Module definition |
| `call` | `send` | Method call |
| `interpolated_string` | `dstr` | String with interpolation |

### Parser Implementation

The Ruby parser at `priv/parsers/ruby/parser.rb`:
- Uses Ruby Prism (`require 'prism'`)
- Strips `_node` suffix for backward compatibility
- Handles syntax errors gracefully
- Supports security pattern detection
- Returns JSON via stdin/stdout for port communication

## Impact

- **No changes to production code** - only test assertions updated
- **No breaking changes** - parser implementation remains unchanged
- **Ruby parser fully functional** - all integration tests passing
- **CI clarity improved** - removed misleading "Ruby parser dependencies" comment

## Related

- **RFC-031:** AST Parser Architecture
- **RFC-036:** AST Comment Detection
- **Prism Documentation:** https://ruby.github.io/prism/
