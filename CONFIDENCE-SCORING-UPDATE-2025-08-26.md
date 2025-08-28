# Confidence Scoring Update - 2025-08-26

## Summary
Updated the AST confidence scoring system to properly handle patterns that don't require user input detection, fixing a critical issue where legitimate vulnerabilities were being filtered out.

## Changes Made

### 1. **Confidence Scorer Enhancement** (`lib/rsolv/ast/confidence_scorer.ex`)
- Replaced blanket 0.7x penalty for missing user input with pattern-specific adjustments
- Pattern categories:
  - **No penalty** (don't need user input): hardcoded_secret, weak_crypto, weak_random, insecure_random
  - **Minimal penalty** (5-8%): code_injection, rce, remote_code_execution, command_injection  
  - **Moderate penalty** (15%): sql_injection, xss, nosql_injection
  - **Small penalty** (10%): unknown patterns without user input

### 2. **Test Coverage** (`test/rsolv/ast/confidence_scorer_realistic_test.exs`)
- Added comprehensive TDD tests covering all pattern types
- Tests verify confidence thresholds are appropriate for each vulnerability type
- All 10 tests passing

## Results

### Before Fix
- eval() without user input: **0.672** ❌ (below 0.7 threshold)
- Hardcoded secrets: **0.56** ❌ (incorrectly penalized)
- RCE patterns: **0.595** ❌ (below threshold)
- SQL injection: **0.577** ❌ (below threshold)

### After Fix
- eval() without user input: **0.912** ✅ (above 0.75 threshold)
- Hardcoded secrets: **0.8** ✅ (no penalty, correct)
- RCE patterns: **0.808** ✅ (above 0.7 threshold)
- SQL injection: **0.701** ✅ (above 0.65 threshold)

## Deployment Status
- ✅ Deployed to staging: `ghcr.io/rsolv-dev/rsolv-platform:staging-confidence-fix-20250826-095915`
- ⏳ Ready for production deployment after cleanup

## Related Documentation
- RFC-042: AST False Positive Reduction Enhancement (covers overall strategy)
- RFC-045: Validation Confidence Scoring (client-side confidence)

## Next Steps

### Before Merging to Main
1. **Commit the changes**:
   - `lib/rsolv/ast/confidence_scorer.ex`
   - `test/rsolv/ast/confidence_scorer_realistic_test.exs`

2. **Clean up test files**:
   - Remove: `test_confidence.exs` (ad-hoc testing)
   - Remove: `test_ast_analysis.exs` (exploratory)
   - Keep: `confidence_scorer_realistic_test.exs` (proper test suite)

3. **Update RFC-042**:
   - Add section on confidence threshold adjustments
   - Document the pattern-specific penalty approach

### No ADR Needed
This is an adjustment to the existing confidence scoring implementation from RFC-042, not a new architectural decision. The core approach remains the same; we've just refined the penalties to be more nuanced.

## Commands to Execute

```bash
# In RSOLV-platform directory
cd /home/dylan/dev/rsolv/RSOLV-platform

# Clean up test files
rm test_confidence.exs
rm test_ast_analysis.exs
rm test/test_python_ast.exs

# Commit the fix
git add lib/rsolv/ast/confidence_scorer.ex
git add test/rsolv/ast/confidence_scorer_realistic_test.exs
git commit -m "fix: Adjust confidence scoring penalties for patterns without user input

- Remove harsh 0.7x penalty for missing user input detection
- Add pattern-specific adjustments based on vulnerability type
- Patterns like hardcoded_secret don't need user input (no penalty)
- Critical patterns like eval/RCE get minimal 5% penalty
- Injection patterns get moderate 15% penalty

This ensures real vulnerabilities aren't filtered out when user input
detection fails, while maintaining good false positive reduction.

Fixes confidence scores:
- eval without input: 0.672 -> 0.912
- hardcoded secrets: 0.56 -> 0.8
- RCE patterns: 0.595 -> 0.808
- SQL injection: 0.577 -> 0.701"

# Push to main
git push origin main
```

## Production Deployment

After merging:
```bash
# Build and deploy production
DOCKER_HOST=10.5.0.5 docker build -t ghcr.io/rsolv-dev/rsolv-platform:production-$(date +%Y%m%d-%H%M%S) -t ghcr.io/rsolv-dev/rsolv-platform:production .
DOCKER_HOST=10.5.0.5 docker push ghcr.io/rsolv-dev/rsolv-platform:production
kubectl set image deployment/rsolv-platform rsolv-platform=ghcr.io/rsolv-dev/rsolv-platform:production -n default
```