# Pattern Test Fix Plan
## Date: 2025-06-28

## Overview
We have 96 failing tests, mostly pattern validation issues. This plan outlines how to systematically fix them.

## Pattern Categories to Fix

### 1. SQL Injection Patterns
**Common Issues:**
- Matching safe parameterized queries (false positives)
- Missing dangerous concatenation patterns (false negatives)
- Regex too broad, catching logging statements

**Fix Strategy:**
- Simplify regex to focus on concatenation operators
- Add negative lookahead for parameterized markers (?, $1, :param)
- Rely on AST enhancement to filter context

### 2. XSS Patterns
**Common Issues:**
- DOM manipulation patterns matching safe operations
- innerHTML assignments with sanitized content flagged
- Missing dangerous sink/source combinations

**Fix Strategy:**
- Focus regex on assignment operators
- Let AST rules check for sanitization functions
- Reduce pattern complexity

### 3. XXE Patterns
**Common Issues:**
- Matching secure XML parser configurations
- Not detecting all vulnerable parser setups
- Framework-specific patterns too generic

**Fix Strategy:**
- Check for security features being explicitly disabled
- Framework-specific patterns for each parser
- AST rules to verify feature flags

### 4. Command Injection Patterns
**Common Issues:**
- Matching safe array-based command execution
- String concatenation patterns too aggressive
- Missing shell metacharacter detection

**Fix Strategy:**
- Distinguish between string and array command forms
- Focus on concatenation with user input
- Check for shell=true flags in subprocess calls

## Implementation Steps

### Phase 1: Gather Failing Tests
```bash
# When we can run tests:
mix test --failed > failing_tests.txt
```

### Phase 2: Group by Pattern Type
- SQL Injection: ~20 tests
- XSS: ~15 tests  
- XXE: ~10 tests
- Command Injection: ~10 tests
- Others: ~41 tests

### Phase 3: Fix Pattern by Pattern
For each pattern:
1. Run individual test file
2. Analyze false positives/negatives
3. Simplify regex
4. Update test expectations
5. Document AST enhancement needs

### Phase 4: Verify with AST Enhancement
- Patterns should have high false positive rate with regex alone
- AST enhancement reduces false positives
- Document confidence scoring adjustments

## Example Fix

### Before:
```elixir
# Too complex, matches too much
regex: ~r/query\s*=.*[\"'`].*\s*\+\s*[^\"'`]+(?:WHERE|FROM|SELECT|INSERT|UPDATE|DELETE)/i
```

### After:
```elixir
# Simpler, relies on AST for context
regex: ~r/(?:query|sql|execute).*?\+/i

# AST enhancement handles:
# - Checking if in database call
# - Detecting parameterized queries
# - Excluding logging contexts
```

## Success Criteria
- All 96 tests passing
- False positive rate documented for each pattern
- AST enhancement rules documented
- Performance impact < 10%

## Next Steps
1. Set up clean test environment (docker/staging)
2. Run failing tests and categorize
3. Start with SQL injection patterns (highest impact)
4. Document each fix in pattern files