# RSOLV Customer Demo Guide (Unified)

**Updated**: 2025-01-15
**Status**: Enhanced with admin provisioning capabilities
**Duration**: 15-18 minutes total (includes admin provisioning)

## Quick Start

```bash
# Pre-flight check (1 minute)
./demo-scripts/demo-pre-flight-check.sh

# Admin login check (NEW)
open https://rsolv.dev/admin/login

# Run demo
./demo-scripts/demo-master.sh
```

## Key Messaging Points

### 🎯 Core Value Proposition
"**Enterprise control meets automation** - RSOLV provides complete administrative oversight while automating security fixes. You maintain full control over customer provisioning, API access, and usage limits."

### 💰 ROI Message
"With typical vulnerabilities costing $7,000+ to fix manually, RSOLV delivers **296,000% ROI** by automating the fix process in minutes instead of days."

### 🎓 Educational Impact
"Every fix comes with tests and educational context, helping your team learn and prevent similar issues in the future."

### 🔐 NEW: Enterprise Security
"Complete administrative control with instant API key revocation, usage monitoring, and full audit trails for compliance."

## Four-Phase Demo Architecture (Enhanced)

### Phase 0: PROVISION (NEW - 2-3 minutes)
**Purpose**: Demonstrate enterprise-grade customer management

```bash
# Navigate to admin dashboard
# Create new customer account
# Generate and configure API key
```

**Demo Script**:
1. Open https://rsolv.dev/admin/login
2. Navigate to Customers section
3. Click "New Customer" button
4. Create "Acme Corp Demo" account with:
   - Email: demo@acmecorp.com
   - Monthly Limit: 1000 fixes
   - Subscription: Professional
5. Navigate to customer detail page
6. Click "Generate New Key"
7. Copy API key (show security features)
8. Configure in GitHub repository settings

**Talk Track**:
"Let me show you how quickly we can provision a new enterprise customer. Our admin dashboard provides complete control over customer accounts, API access, and usage limits. Notice the security features - API keys can be instantly revoked, and all actions are fully audited for compliance."

### Phase 1: SCAN (2-3 minutes)
**Purpose**: Detect vulnerabilities without disrupting your workflow

```bash
# Trigger: Push to repository
# Action: RSOLV scans code
# Output: GitHub issues with rsolv:detected label
```

**Demo Script**:
1. Show the NodeGoat repository (vulnerable by design)
2. Trigger scan (or show recent scan results)
3. Highlight: "30 vulnerabilities detected in 56 seconds"
4. Show Issue #42 (NoSQL injection) as example
5. Emphasize: "No automatic fixes - you're in control"

**Talk Track**:
"RSOLV continuously monitors your code for security vulnerabilities. In this demo repository, it found 30 issues in under a minute. Notice each issue is clearly labeled and documented, but nothing happens automatically - you maintain full control."

### Phase 2: VALIDATE (Optional, 1-2 minutes)
**Purpose**: Reduce false positives with AST analysis

```bash
# Trigger: Add rsolv:validate label
# Action: Deep code analysis
# Output: Validation results added to issue
```

**Demo Script**:
1. Add `rsolv:validate` label to Issue #42
2. Show workflow running (or existing validation)
3. Point out line numbers and code snippets
4. Mention: "99% accuracy rate with AST validation"

**Talk Track**:
"For critical issues, you can request validation. RSOLV uses abstract syntax tree analysis to confirm the vulnerability and provide exact code locations. This optional step virtually eliminates false positives."

### Phase 3: MITIGATE (3-8 minutes)
**Purpose**: Generate production-ready fixes with tests

```bash
# Trigger: Add rsolv:automate label
# Action: Generate fix using Claude Code
# Output: Pull request with fix, tests, and education
```

**Demo Script**:
1. Add `rsolv:automate` label to Issue #42
2. Watch GitHub Actions workflow (or show PR #43)
3. Open PR #43 to show:
   - Security fix implementation
   - New tests for the fix
   - Educational comments
   - Before/after comparison
4. Highlight the quality of the generated code

**Talk Track**:
"When you're ready to fix an issue, simply add the automate label. RSOLV uses advanced AI with credential vending to generate a complete solution. Look at this PR - it's not just a fix, but includes tests and educational context. This is production-ready code that your team would be proud to write."

### Phase 4: MONITOR (NEW - 2 minutes)
**Purpose**: Show administrative oversight and control

```bash
# Return to admin dashboard
# Show customer usage statistics
# Demonstrate API key management
```

**Demo Script**:
1. Return to https://rsolv.dev/admin/customers
2. Click on "Acme Corp Demo" customer
3. Show usage statistics:
   - Current usage: 1/1000 fixes
   - Usage graph showing trend
4. Show API keys section:
   - Active keys with last used timestamps
   - Ability to deactivate instantly
5. Navigate to admin dashboard
6. Show recent activity feed

**Talk Track**:
"From the administrative dashboard, you have complete visibility into customer usage and system health. You can see that Acme Corp has used 1 of their 1000 monthly fixes. We can track patterns, adjust limits, and even instantly revoke access if needed. This level of control is essential for enterprise deployments."

## Technical Architecture (Optional Deep Dive)

### Credential Vending System
"Instead of storing API keys in GitHub, RSOLV uses temporary credential vending. Each fix request gets fresh, short-lived credentials that expire after use."

### Security Model
- No source code storage
- Client-side encryption
- Sandboxed execution
- Audit logging

### Integration Points
- GitHub Actions (primary)
- Linear (issue tracking)
- Slack (notifications)
- Custom webhooks

## Demo Environment Details

### Repository
- **URL**: https://github.com/RSOLV-dev/nodegoat-vulnerability-demo
- **Type**: OWASP NodeGoat (intentionally vulnerable)
- **Issues**: #42 (NoSQL injection example)
- **PRs**: #43 (example fix with tests)

### Credentials (Now Working!)
- **RSOLV_API_KEY**: Available in environment
- **Credential Vending**: Fixed in ADR-023
- **No GitHub secrets needed**: Uses vended credentials

### Timing Guidelines (Updated)
| Phase | Target | Maximum | Notes |
|-------|--------|---------|-------|
| PROVISION | 2-3 min | 3 min | NEW: Live customer creation |
| SCAN | 2-3 min | 3 min | 56 seconds typical ✅ |
| VALIDATE | 1-2 min | 2 min | Optional, 45 seconds typical ✅ |
| MITIGATE | 3-8 min | 8 min | 48 seconds typical ✅ |
| MONITOR | 2 min | 2 min | NEW: Admin dashboard review |
| **TOTAL** | **11-17 min** | **18 min** | Complete enterprise demo |

## Fallback Scenarios (Enhanced)

### If Live Demo Fails
1. **Admin Dashboard Saves the Day** (NEW)
   - Generate new API key on the spot
   - Adjust customer limits if needed
   - Show existing customer with usage history
   - Use pre-created "Demo Customer" account

2. **Use Existing Artifacts**
   - Issue #42: Complete vulnerability analysis
   - PR #43: Production-ready fix with tests
   - Existing customers in admin dashboard
   - These are real, working examples

3. **Focus on Enterprise Value**
   - Administrative control and oversight
   - Multi-tenant customer management
   - Usage tracking and billing integration
   - Cost savings: $7,000+ per vulnerability
   - Time savings: Minutes vs days

4. **Show Architecture Diagrams**
   - Four-phase flow diagram (with provisioning)
   - Admin dashboard architecture
   - Security model with API key management
   - ROI calculation breakdown

## Pre-Recording Checklist

### Environment Setup ✅
```bash
# Check API access
echo $RSOLV_API_KEY  # Should show key

# Test credential vending (fixed in ADR-023)
./demo-scripts/demo-pre-flight-check.sh

# Verify GitHub CLI
gh auth status
```

### Repository State ✅
```bash
# Check for clean state
gh issue list --repo RSOLV-dev/nodegoat-vulnerability-demo --state open

# Verify example artifacts exist
gh issue view 42 --repo RSOLV-dev/nodegoat-vulnerability-demo
gh pr view 43 --repo RSOLV-dev/nodegoat-vulnerability-demo
```

### Recent Fixes Applied ✅
- **Credential Vending**: Fixed in `claude-code-cli-retry.ts`
- **Process.env Setting**: Now properly passes API keys
- **Test Coverage**: Added regression tests
- **Documentation**: ADR-023 documents the fix

## Demo Script (Detailed)

### Opening (30 seconds)
"I'm going to show you RSOLV in action on a real vulnerable application. This is NodeGoat, an OWASP training application with intentional security vulnerabilities."

### Scan Phase (2 minutes)
1. Show repository overview
2. Point out it's a real Node.js application
3. Show GitHub Actions tab
4. Run scan or show recent results
5. Open issues tab - "30 vulnerabilities in 56 seconds"
6. Click Issue #42 as example
7. "Notice the clear description and rsolv:detected label"

### Validate Phase (1 minute, optional)
1. "Let's validate this is a real vulnerability"
2. Add rsolv:validate label
3. Show validation results in issue comments
4. "AST analysis confirms: NoSQL injection on line 47"

### Mitigate Phase (3 minutes)
1. "Now let's fix this vulnerability"
2. Add rsolv:automate label
3. Show GitHub Actions running
4. Open PR #43 when ready
5. Walk through the code changes
6. Highlight the test coverage
7. Point out educational comments
8. "This is production-ready code"

### Business Value (2 minutes)
1. "Each vulnerability typically costs $7,000+ to fix manually"
2. "RSOLV fixed this in 48 seconds"
3. "That's a 296,000% ROI"
4. "And your team learns from every fix"

### Closing (30 seconds)
"RSOLV gives you enterprise-grade security automation while keeping you in complete control. You decide what to scan, what to validate, and what to fix. We handle the implementation."

## Post-Demo Cleanup

```bash
# Remove any test labels
gh issue edit 42 --repo RSOLV-dev/nodegoat-vulnerability-demo --remove-label "rsolv:validate,rsolv:automate"

# Archive any test artifacts
./demo-scripts/cleanup.sh
```

## Support Resources

- **Technical Issues**: Check ADR-023 for credential vending fix
- **Demo Scripts**: All in `demo-scripts/` directory
- **Fallback Examples**: Issue #42, PR #43
- **Architecture Docs**: See RFCs and ADRs directories

## Success Metrics

✅ Scan completes in < 3 minutes  
✅ Issues created with proper labels  
✅ PR includes fix, tests, and education  
✅ Clear value proposition communicated  
✅ Customer understands they stay in control  

---

**Remember**: The demo works best when you emphasize that RSOLV augments your team's capabilities rather than replacing them. "You stay in control" is the key message.