# Root Cause Analysis: JavaScript eval() CODE_INJECTION Not Detected

## Problem Statement

E2E validation on RailsGoat revealed that the JavaScript `eval()` pattern (CODE_INJECTION, CWE-94) is **not being detected** by RSOLV-action v3.8.1.

**Evidence:**
- File: `app/assets/javascripts/jquery.snippet.js` line 737
- Code: `eval(request.responseText);`
- Scanned: YES (logs show 2 vulnerabilities found in this file)
- Detected: XSS (line 401) and ReDoS (line 768)
- **Missed**: The critical `eval()` CODE_INJECTION on line 737

## Investigation Findings

### 1. Platform Pattern Definition ✓ CORRECT

**Location:** `/home/dylan/dev/rsolv/lib/rsolv/security/patterns/javascript/eval_user_input.ex`

```elixir
%Pattern{
  id: "js-eval-user-input",
  name: "Dangerous eval() with User Input",
  type: :code_injection,  # Changed from :rce in PR #113 (Nov 9, 2025)
  severity: :critical,
  regex: ~r/^(?!.*\/\/).*eval\s*\(.*?(?:req\.|request\.|params\.|query\.|body\.|user|input|data|Code)/im,
  cwe_id: "CWE-94",
  ...
}
```

**Regex Test Result:** ✓ MATCHES `eval(request.responseText)`

```javascript
// test-regex.js output
Test code: eval(request.responseText);
Match result: true
```

### 2. Pattern Registration ✓ CORRECT

**Location:** `/home/dylan/dev/rsolv/lib/rsolv/security/patterns/javascript.ex`

- Line 27: `EvalUserInput` is imported
- Line 72: `eval_user_input()` is included in `all()` function
- Function returns 30 patterns total

### 3. RSOLV-Action Type Support ✓ CORRECT

**Location:** `src/security/types.ts:13`
```typescript
CODE_INJECTION = 'code_injection',
```

**Location:** `src/security/pattern-api-client.ts:287`
```typescript
'code_injection': VulnerabilityType.CODE_INJECTION,
```

### 4. RailsGoat Scan Configuration ✓ CORRECT

**Evidence from logs:**
```
rsolvApiKey: ***
api_url: https://rsolv-staging.com
apiKeyLength: 18
apiKeyPrefix: "rsolv_test..."
Fetched 30 javascript patterns from API
```

- API key was present and valid
- 30 patterns were fetched (full pattern set, not demo patterns which are only 5)
- File was scanned (other vulnerabilities were found)

## Root Cause Hypothesis

### Primary Hypothesis: Pattern Not in API Response

The most likely cause is that **`js-eval-user-input` pattern is not being returned by the staging API**, despite being defined in the codebase.

**Evidence:**
1. **Recent Type Change:** PR #113 changed pattern type from `:rce` → `:code_injection` on Nov 9, 2025 at 15:47
2. **RailsGoat Test:** Ran on Nov 10, 2025 at 15:38 (20+ hours later)
3. **Pattern Count:** Logs show exactly 30 patterns, which matches `javascript.ex all()` count
4. **Staging URL:** Test used `https://rsolv-staging.com` not production API

**Possible Sub-Causes:**

**A. Staging Not Deployed After PR #113**
- PR #113 was merged to main on Nov 9
- Staging environment may not have been redeployed with this change
- Staging might still be serving patterns with old `:rce` type

**B. API Pattern Cache Not Cleared**
- Platform may be caching patterns
- Cache might contain pre-PR #113 patterns
- Cache invalidation might not have occurred after merge

**C. Pattern Type Filter Issue**
- Platform API might be filtering out `:code_injection` type patterns
- Type mapping from Elixir atom to JSON string might have issues
- Enhanced format serialization might be dropping the pattern

**D. Database/Pattern Server State**
- Pattern Server (GenServer) might not have reloaded patterns
- Database might have stale pattern data
- Pattern loading from filesystem might be failing

### Secondary Hypothesis: Pattern Detection Failure

Less likely, but the pattern might be in the response but failing to detect due to:

**A. Regex Serialization Issue**
- Elixir regex → JSON string → JavaScript regex conversion failure
- Flags might not be preserved correctly
- Pattern might be malformed after serialization

**B. Worker Thread Issue**
- Pattern might fail when executed in worker thread
- Timeout or error might be swallowed
- Detection result might not be returned properly

## Verification Steps

### Step 1: Verify API Response Content

```javascript
// Test what staging actually returns
const response = await fetch(
  'https://rsolv-staging.com/api/v1/patterns?language=javascript&format=enhanced',
  { headers: { 'x-api-key': 'REAL_API_KEY' } }
);
const data = await response.json();

// Check if js-eval-user-input is present
const evalPattern = data.patterns.find(p => p.id === 'js-eval-user-input');
console.log('js-eval-user-input present:', !!evalPattern);
if (evalPattern) {
  console.log('Type:', evalPattern.type);
  console.log('Regex:', evalPattern.regex);
}

// List all pattern IDs and types
data.patterns.forEach(p => {
  if (p.type === 'code_injection') {
    console.log(`CODE_INJECTION: ${p.id}`);
  }
});
```

### Step 2: Check Staging Deployment Status

```bash
# Check what commit staging is running
curl https://rsolv-staging.com/api/health
# Look for version/commit info

# Compare with main branch
cd /home/dylan/dev/rsolv
git log --oneline -1 main
```

### Step 3: Test Pattern Detection Locally

```bash
cd /var/tmp/vibe-kanban/worktrees/7b29-javascript-eval

# Create test file with eval
echo 'eval(request.responseText);' > test-eval.js

# Run scanner with action locally
npm test -- --grep "eval"
```

## Recommended Solution

### Option 1: Redeploy Staging (Preferred)

If staging hasn't been deployed with PR #113 changes:

```bash
# Ensure staging is updated to main
cd /home/dylan/dev/rsolv
git checkout main
git pull origin main

# Deploy to staging
# (deployment command depends on infrastructure setup)
```

### Option 2: Clear Pattern Cache

If patterns are cached:

```elixir
# In platform IEx console
Rsolv.Security.PatternServer.reload_patterns()
# or
Rsolv.Security.PatternServer.clear_cache()
```

### Option 3: Fix Pattern Server Loading

If pattern loading is broken:

1. Check Pattern Server logs for errors
2. Verify pattern modules are compiled
3. Ensure pattern files are accessible
4. Restart Pattern Server GenServer

## Success Criteria

After fix is applied:

- [ ] `js-eval-user-input` appears in API response
- [ ] Pattern has `type: "code_injection"`
- [ ] Pattern regex is properly serialized
- [ ] `eval(request.responseText)` is detected in RailsGoat
- [ ] Issue is created with type `code_injection`
- [ ] CWE-94 is correctly mapped
- [ ] E2E validation passes

## Next Steps

1. **Immediate:** Get real API key for staging and verify hypothesis with Step 1
2. **If confirmed:** Deploy staging with PR #113 changes or clear cache
3. **Re-run:** RailsGoat E2E validation test
4. **Verify:** Pattern is detected correctly
5. **Document:** Update E2E validation results in RFC-067

## Related Files

### Platform (rsolv)
- `lib/rsolv/security/patterns/javascript/eval_user_input.ex` - Pattern definition
- `lib/rsolv/security/patterns/javascript.ex` - Pattern registration
- `lib/rsolv/security/pattern.ex` - Pattern struct and API serialization
- `lib/rsolv/security/ast_pattern.ex` - Pattern loading logic
- `lib/rsolv_web/controllers/api/v1/pattern_controller.ex` - API endpoint

### Action (rsolv-action)
- `src/security/types.ts` - VulnerabilityType enum
- `src/security/pattern-api-client.ts` - API client and type mapping
- `src/security/detector-worker.js` - Pattern detection worker
- `src/security/minimal-patterns.ts` - Fallback patterns

### Documentation
- `RFCs/RFC-067-GITHUB-MARKETPLACE-PUBLISHING.md` - E2E validation requirements
- PR #113: https://github.com/RSOLV-dev/rsolv/pull/113

## Timeline

- **Nov 9, 2025 15:47:** PR #113 merged to main (code_injection type added)
- **Nov 10, 2025 15:38:** RailsGoat E2E validation run (pattern not detected)
- **Nov 10, 2025:** Investigation conducted (this document)

## Priority

**CRITICAL** - Blocks E2E validation and GitHub Marketplace publishing timeline
