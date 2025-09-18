# RSOLV Demo Validation Strategy

**Created**: 2025-09-02
**Updated**: 2025-01-15
**Purpose**: Ensure customer demo video recording succeeds without issues, including admin provisioning

## Executive Summary

This document outlines a comprehensive programmatic validation approach for the RSOLV customer demo. The strategy ensures all demo components work reliably before recording, minimizing retakes and ensuring a smooth demonstration.

## Three-Layer Validation Approach

### Layer 1: Pre-Flight Check (Non-Destructive)
**Script**: `demo-scripts/demo-pre-flight-check.sh`
**When**: Before each recording attempt
**Duration**: ~1 minute

Validates:
- ✅ Environment (GitHub CLI, auth, tools)
- ✅ Repository state (clean issues, example artifacts)
- ✅ Vulnerable code exists unchanged
- ✅ GitHub Actions enabled and accessible
- ✅ API connectivity (simulated)
- ✅ Expected timings documented
- ✅ Admin dashboard access (NEW)
- ✅ Customer provisioning permissions (NEW)

**Key Feature**: Non-destructive - only reads state, doesn't modify anything

### Layer 2: Rehearsal Mode (Full Run-Through)
**Script**: `demo-scripts/demo-rehearsal.sh`
**When**: Before first recording, after major changes
**Duration**: 18-22 minutes

Executes:
- 🆕 PROVISION → Creates test customer account (NEW)
- 🔄 Complete SCAN → VALIDATE → MITIGATE flow
- 📊 MONITOR → Reviews usage metrics (NEW)
- ⏱️ Measures actual phase timings
- 📊 Validates outputs at each step
- 🎯 Tests issue creation, labeling, PR generation
- 📈 Provides timing analysis and recommendations

**Key Feature**: Destructive - creates real issues/PRs (marked as REHEARSAL)

### Layer 3: Continuous Validation
**Script**: `demo-scripts/nodegoat-demo-test.sh`  
**When**: Quick spot checks during demo  
**Duration**: ~30 seconds  

Shows:
- 📋 Current repository state
- 🔍 Existing demo artifacts (Issue #42, PR #43)
- 💬 Key talking points reminder
- 🚀 Recent workflow runs

**Key Feature**: Read-only quick status check

## Critical Success Factors

### 1. Timing Requirements
| Phase | Target Time | Maximum Time | Action if Exceeded |
|-------|------------|--------------|-------------------|
| PROVISION | 2-3 min | 3 min | Use existing customer (NEW) |
| SCAN | 2-3 min | 3 min | Show pre-recorded or edit |
| VALIDATE | 1-2 min | 2 min | Skip in demo (optional) |
| MITIGATE | 3-8 min | 8 min | Speed up in editing |
| MONITOR | 2 min | 2 min | Show dashboard only (NEW) |

### 2. Label Management
**Critical**: Issues must be created with `rsolv:detected` NOT `rsolv:automate`
- ✅ `rsolv:detected` - Safe, doesn't trigger fixes
- ❌ `rsolv:automate` - Triggers immediate fix generation
- Validate in `issue-creator.ts:50`

### 3. Fallback Options
If live demo fails:
- **Option A**: Use existing artifacts (Issue #42, PR #43)
- **Option B**: Show recording of successful rehearsal
- **Option C**: Trigger fix on different vulnerability
- **Option D**: Focus on business value discussion
- **Option E**: Generate new API key from admin dashboard (NEW)
- **Option F**: Show existing customer with usage history (NEW)

## Validation Checklist

### Before Recording
```bash
# 1. Run pre-flight check
./demo-scripts/demo-pre-flight-check.sh

# 2. Admin login check (NEW)
open https://rsolv.dev/admin/login
# Verify access to admin dashboard

# 3. If first recording or after changes
./demo-scripts/demo-rehearsal.sh

# 4. Clean repository state
gh issue list --repo RSOLV-dev/nodegoat-vulnerability-demo --state open
# Should show 0 open issues (except examples)
```

### During Recording
```bash
# Quick status check if needed
./demo-scripts/nodegoat-demo-test.sh

# Main demo flow
./demo-scripts/demo-master.sh
```

### After Recording
```bash
# Clean up any test artifacts
gh issue list --repo RSOLV-dev/nodegoat-vulnerability-demo | grep REHEARSAL
# Close any rehearsal issues/PRs
```

## Key Validation Points

### Phase 0: PROVISION (NEW)
✅ **MUST**: Access admin dashboard at /admin/customers
✅ **MUST**: Create new customer with email and limits
✅ **MUST**: Generate API key successfully
✅ **MUST**: Complete within 3 minutes
❌ **MUST NOT**: Show any production customer data

### Phase 1: SCAN
✅ **MUST**: Create issues with `rsolv:detected` label  
✅ **MUST**: Complete within 3 minutes  
✅ **MUST**: Detect NoSQL injection vulnerability  
❌ **MUST NOT**: Auto-trigger fixes  

### Phase 2: VALIDATE (Optional)
✅ **MUST**: Accept `rsolv:validate` label  
✅ **MUST**: Add "## Validation Results" to issue  
✅ **SHOULD**: Complete within 2 minutes  
✅ **SHOULD**: Include line numbers and snippets  

### Phase 3: MITIGATE
✅ **MUST**: Accept `rsolv:automate` label
✅ **MUST**: Auto-validate if not already validated
✅ **MUST**: Generate PR within 8 minutes
✅ **MUST**: Include fix, tests, and education
✅ **MUST**: Show correct before/after code

### Phase 4: MONITOR (NEW)
✅ **MUST**: Return to admin dashboard
✅ **MUST**: Show customer usage statistics
✅ **MUST**: Demonstrate API key management
✅ **SHOULD**: Show usage graph and trends
✅ **SHOULD**: Highlight instant revocation capability  

## Emergency Procedures

### If Scan Fails
1. Check GitHub Actions logs
2. Verify API credentials
3. Use existing detected issues as fallback

### If Fix Generation Fails
1. Show existing PR #43 as example
2. Explain the process conceptually
3. Focus on ROI and business value

### If Timing Exceeds Targets
1. Continue recording (edit later)
2. Mention "processing complex codebase"
3. Speed up waiting in post-production

## Programmatic Test Implementation

### Automated Test Suite
```bash
#!/bin/bash
# Complete demo validation suite

# Non-destructive tests
./demo-pre-flight-check.sh || exit 1

# Optional: Full rehearsal
read -p "Run full rehearsal? (y/n) " -n 1 -r
if [[ $REPLY =~ ^[Yy]$ ]]; then
    ./demo-rehearsal.sh
fi

# Final confirmation
echo "Demo validation complete. Ready to record!"
```

### Continuous Integration
Consider adding to CI/CD:
```yaml
name: Demo Validation
on:
  schedule:
    - cron: '0 8 * * 1'  # Weekly on Mondays
  workflow_dispatch:

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run pre-flight check
        run: ./demo-scripts/demo-pre-flight-check.sh
      - name: Test demo scripts
        run: |
          bash -n ./demo-scripts/*.sh
          shellcheck ./demo-scripts/*.sh
```

## Success Metrics

### Technical Success
- ✅ All phases complete within time targets
- ✅ No errors during demo flow
- ✅ Correct labels applied
- ✅ PR generated with proper content
- ✅ Customer provisioned successfully (NEW)
- ✅ API key generated and configured (NEW)
- ✅ Usage metrics displayed correctly (NEW)

### Business Success
- ✅ Clear value proposition communicated
- ✅ ROI message delivered (296,000%)
- ✅ User control emphasized
- ✅ Educational aspect highlighted
- ✅ Enterprise control demonstrated (NEW)
- ✅ Multi-tenant capability shown (NEW)
- ✅ Instant administrative actions showcased (NEW)

## Conclusion

This enhanced validation strategy ensures:
1. **Reliability**: Multiple validation checkpoints
2. **Speed**: Quick pre-flight checks
3. **Confidence**: Full rehearsal capability
4. **Recovery**: Clear fallback options
5. **Enterprise Ready**: Admin provisioning validation (NEW)
6. **Complete Control**: Customer management verification (NEW)

Run `./demo-scripts/demo-pre-flight-check.sh` before every recording to ensure success, including admin dashboard access verification.