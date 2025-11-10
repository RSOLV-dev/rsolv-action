# Investigation Summary: JavaScript eval() CODE_INJECTION Detection Failure

**Date:** November 10, 2025
**Issue:** JavaScript `eval()` with user input not detected in RailsGoat E2E validation
**Priority:** CRITICAL - Blocks GitHub Marketplace publishing
**Investigator:** Claude (RSOLV AI Assistant)

## Executive Summary

The `js-eval-user-input` pattern (CODE_INJECTION, CWE-94) failed to detect `eval(request.responseText)` on line 737 of `app/assets/javascripts/jquery.snippet.js` in the RailsGoat E2E validation test.

**Key Finding:** The pattern exists and is correctly defined in the platform codebase, but the root cause of detection failure requires API-level verification with real credentials.

## Investigation Completed

### ✓ Verified: Pattern Definition
- **Location:** `lib/rsolv/security/patterns/javascript/eval_user_input.ex`
- **Pattern ID:** `js-eval-user-input`
- **Type:** `:code_injection` (changed from `:rce` in PR #113, Nov 9, 2025)
- **Regex:** Tested and **MATCHES** `eval(request.responseText)` ✓

### ✓ Verified: Pattern Registration
- Pattern properly imported in `javascript.ex`
- Included in `all()` function (returns 30 patterns)
- Pattern module compiles and loads correctly

### ✓ Verified: Action Type Support
- `VulnerabilityType.CODE_INJECTION` exists in types.ts
- Type mapping `'code_injection' → CODE_INJECTION` exists in pattern-api-client.ts
- Action should handle code_injection type correctly

### ✓ Verified: Scan Configuration
- RailsGoat scan used valid API key (`rsolv_test...`, 18 chars)
- Fetched 30 JavaScript patterns (full access, not demo)
- File was scanned (2 other vulnerabilities detected: XSS, ReDoS)

## Primary Hypothesis

**The `js-eval-user-input` pattern is not being returned by the staging API**, despite being defined in the codebase.

### Evidence Supporting This Hypothesis:

1. **Recent Type Change:** PR #113 merged Nov 9, 2025 at 15:47
   - Changed pattern type from `:rce` → `:code_injection`
   - Added `code_injection` to platform vulnerability type enum

2. **Deployment Gap:** RailsGoat test ran Nov 10, 2025 at 15:38
   - 20+ hours after PR merge
   - Staging may not have been redeployed with PR #113 changes

3. **Staging API Endpoint:** Test used `https://rsolv-staging.com`
   - Different from production API (`https://api.rsolv.dev`)
   - May be running older code or serving cached patterns

### Possible Root Causes (In Order of Likelihood):

**1. Staging Not Redeployed After PR #113 (Most Likely)**
- Staging still serving patterns with `:rce` type
- Pattern type filter or mapper doesn't recognize new type
- Pattern appears in codebase but not in API response

**2. API Pattern Cache Not Cleared**
- Platform caches patterns for performance
- Cache contains pre-PR #113 patterns
- Cache TTL hasn't expired or wasn't manually cleared

**3. Pattern Type Filtering**
- API might filter patterns by recognized types
- `code_injection` might not be in filter whitelist
- Pattern excluded from response

**4. Pattern Server State Issue**
- Pattern Server (GenServer) didn't reload
- Pattern modules not recompiled
- Filesystem access issue

## Verification Required

**CRITICAL NEXT STEP:** Run the verification script with real API credentials:

```bash
# Get real API key from staging environment or secrets manager
export RSOLV_API_KEY="rsolv_test_actual_key_here"

# Run comprehensive API test
node verify-api-patterns.js
```

This will definitively determine:
- ✓ Whether `js-eval-user-input` is in the API response
- ✓ Whether it has `type: "code_injection"` or `type: "rce"`
- ✓ Whether the regex is properly serialized
- ✓ Whether staging is serving old patterns

## Recommended Actions

### Immediate (After Verification):

**If pattern is MISSING from API:**
1. Deploy staging with latest main branch (includes PR #113)
2. Or clear platform pattern cache
3. Restart Pattern Server if needed
4. Re-run RailsGoat E2E validation

**If pattern is PRESENT but type is "rce":**
1. Confirm staging is running pre-PR #113 code
2. Deploy staging with main branch
3. Verify deployment with health check
4. Re-run validation

**If pattern is PRESENT with "code_injection" type:**
1. Investigation shifts to RSOLV-action side
2. Test pattern detection locally
3. Check action logs for errors
4. Verify regex reconstruction logic

### Follow-up:

1. **Document Deployment Process:**
   - When was staging last deployed?
   - What commit is staging running?
   - How to verify staging version?

2. **Add Monitoring:**
   - Pattern API health checks
   - Pattern count verification
   - Type distribution monitoring

3. **Improve E2E Testing:**
   - Test against specific known vulnerabilities
   - Verify expected pattern counts
   - Check for pattern type consistency

## Files Created

1. **`ROOT_CAUSE_ANALYSIS.md`** - Comprehensive technical analysis
2. **`verify-api-patterns.js`** - Diagnostic test script
3. **`test-regex.js`** - Regex validation test
4. **`test-platform-patterns.js`** - Demo API test
5. **`test-staging-patterns.js`** - Staging API test (needs real key)
6. **`INVESTIGATION_SUMMARY.md`** - This document

## Success Criteria

After fix is applied and verified:

- [ ] `js-eval-user-input` pattern appears in API response
- [ ] Pattern has `type: "code_injection"` (not `"rce"`)
- [ ] Pattern regex matches `eval(request.responseText)`
- [ ] RailsGoat scan detects the vulnerability
- [ ] Issue created with type `code_injection`
- [ ] CWE-94 correctly mapped
- [ ] E2E validation passes completely

## Timeline

| Date/Time | Event |
|-----------|-------|
| Nov 9, 2025 15:47 | PR #113 merged to main (code_injection type added) |
| Nov 10, 2025 15:38 | RailsGoat E2E validation (eval not detected) |
| Nov 10, 2025 16:30 | Investigation conducted |
| Nov 10, 2025 17:00 | Awaiting verification with real API key |

## Related Resources

### Platform (rsolv)
- PR #113: https://github.com/RSOLV-dev/rsolv/pull/113
- Commit: 730b0972 (merge) / 2a2382dd (type change)
- Branch: `vk/46eb-add-code-injecti` (merged to main)

### Action (rsolv-action)
- Version: v3.8.1
- Repository: https://github.com/RSOLV-dev/rsolv-action

### Testing
- RailsGoat: https://github.com/RSOLV-dev/railsgoat
- Workflow Run: https://github.com/RSOLV-dev/railsgoat/actions/runs/19237082696
- Vulnerable File: `app/assets/javascripts/jquery.snippet.js:737`

### Documentation
- RFC-067: GitHub Marketplace Publishing
- E2E Validation Requirements

## Next Step for User

**ACTION REQUIRED:**

The investigation has identified the most likely cause but cannot proceed without API credentials. Please:

1. Obtain the **real RSOLV API key** used in the RailsGoat test
   - Check GitHub secrets in railsgoat repository
   - Or get staging API key from secrets manager
   - Key format: `rsolv_test_...` (18 characters)

2. Run the verification script:
   ```bash
   export RSOLV_API_KEY="[actual_key_here]"
   node verify-api-patterns.js
   ```

3. Share the output with the team or review it to confirm:
   - Whether pattern is in API response
   - Current pattern type (`code_injection` vs `rce`)
   - Staging deployment status

4. Based on results, apply the appropriate fix from the "Recommended Actions" section above

The verification script will provide a clear diagnosis and specific remediation steps.

---

**Investigation Status:** ✓ COMPLETE (awaiting API verification)
**Blocking Issue:** Need real API credentials for final confirmation
**Confidence Level:** HIGH (pattern definition correct, likely deployment issue)
