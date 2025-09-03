# RSOLV Customer Demo Guide (Unified)

**Updated**: 2025-09-02  
**Status**: Ready for recording with credential vending fix applied  
**Duration**: 12-15 minutes total  

## Quick Start

```bash
# Pre-flight check (1 minute)
./demo-scripts/demo-pre-flight-check.sh

# Run demo
./demo-scripts/demo-master.sh
```

## Key Messaging Points

### 🎯 Core Value Proposition
"**You stay in control** - RSOLV finds and validates vulnerabilities, but you decide what to fix and when."

### 💰 ROI Message
"With typical vulnerabilities costing $7,000+ to fix manually, RSOLV delivers **296,000% ROI** by automating the fix process in minutes instead of days."

### 🎓 Educational Impact
"Every fix comes with tests and educational context, helping your team learn and prevent similar issues in the future."

## Three-Phase Architecture

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

### Timing Guidelines
| Phase | Target | Maximum | Actual (Recent) |
|-------|--------|---------|-----------------|
| SCAN | 2-3 min | 3 min | 56 seconds ✅ |
| VALIDATE | 1-2 min | 2 min | 45 seconds ✅ |
| MITIGATE | 3-8 min | 8 min | 48 seconds ✅ |

## Fallback Scenarios

### If Live Demo Fails
1. **Use Existing Artifacts**
   - Issue #42: Complete vulnerability analysis
   - PR #43: Production-ready fix with tests
   - These are real, working examples

2. **Focus on Business Value**
   - Cost savings: $7,000+ per vulnerability
   - Time savings: Minutes vs days
   - Education value: Team upskilling

3. **Show Architecture Diagrams**
   - Three-phase flow diagram
   - Security model visualization
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