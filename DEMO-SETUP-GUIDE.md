# RSOLV Demo Setup Guide - Complete Customer Journey

**Date**: 2025-08-07  
**Purpose**: Accurate guide for demonstrating RSOLV's ACTUAL functionality  
**Duration**: Record ~30-45 minutes, edit to ~12 minutes  
**Setup Time**: ~30 minutes to prepare demo environment  

## Current Implementation Status

### ✅ What EXISTS and WORKS:
- **GitHub Action v3.0.0** with three-phase architecture
- **Vulnerability scanning** with pattern matching
- **Issue creation** with detailed reports
- **Automated fixing** via rsolv:automate label
- **PR generation** with educational content
- **Test generation** and validation
- **Claude Code SDK integration** for fixes

### ❌ What DOESN'T EXIST (Don't Demo):
- Dashboard at rsolv.dev
- API key management UI
- Billing/payment system
- Usage tracking/metrics
- Webhook notifications
- Email signup flow
- ConvertKit integration
- Trial limits

## Demo Repository Setup

### Primary: OWASP NodeGoat (RECOMMENDED)
```bash
# Industry-standard vulnerable app by OWASP
cd /home/dylan/dev/rsolv/nodegoat-vulnerability-demo

# Key vulnerability:
# - app/data/allocations-dao.js:78 (NoSQL injection with $where)
# - Issue #42: Critical NoSQL injection (ready to demo)
# - PR #43: High-quality fix already generated
# - Workflow: Uses RSOLV-dev/rsolv-action@main
```

### Alternative: Custom E-commerce Demo
```bash
# Simple SQL injection demo
cd /home/dylan/dev/rsolv/demo-repos/demo-ecommerce-security-github

# Has vulnerabilities in:
# - src/auth/login.js (SQL injection)
# - Already has workflow file updated to v3.0.0
# - Has existing issues #12-17
```

### Or Create New Vulnerabilities
```javascript
// Example: SQL Injection (routes/search.js)
app.get('/search', (req, res) => {
  const searchTerm = req.query.q;
  // VULNERABLE: Direct string concatenation
  const query = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%'`;
  db.query(query, (err, results) => {
    res.json(results);
  });
});
```

## Realistic Demo Flow

### 1. Introduction (2 minutes)
```
"Today I'm demonstrating RSOLV on NodeGoat - OWASP's deliberately vulnerable 
Node.js application used by security professionals worldwide. If RSOLV can 
automatically fix these intentionally complex vulnerabilities, imagine what 
it can do for your production code."
```

### 2. Repository Setup (3 minutes)
```bash
# Show the workflow file
cat .github/workflows/rsolv.yml

# Explain the configuration
# - Triggers on issues with rsolv:automate label
# - Uses RSOLV-dev/rsolv-action@v3.0.0
# - Requires RSOLV_API_KEY secret
```

**For API Key:** 
- Use environment variable or hardcoded test key
- Say: "Contact us for early access to get your API key"
- Don't show a dashboard that doesn't exist

### 3. Trigger Security Scan (5-7 minutes)
```bash
# Option 1: Create an issue manually
gh issue create --title "Security scan requested" \
  --body "Please scan for vulnerabilities" \
  --label "rsolv:automate"

# Option 2: Show existing issue
gh issue view 16
```

**What Actually Happens:**
- Action triggers on label
- Scans repository files
- Identifies vulnerabilities
- Creates detailed GitHub issues

### 4. Review Created Issues (3 minutes)
Show the actual issue format we create:
- Specific file and line numbers
- Code snippets
- Security impact explanation
- Remediation suggestions

### 5. Fix Generation (10-15 minutes real time)
```bash
# This is the real process - let it run
# Apply label to trigger fix
gh issue edit 16 --add-label "rsolv:automate"

# Watch the action run
gh run watch
```

**What Actually Happens:**
1. Reads issue content
2. Analyzes vulnerability context
3. Uses Claude Code SDK to generate fix
4. Creates comprehensive PR

### 6. Pull Request Review (5 minutes)
Show the ACTUAL PR features:
- Complete fix with proper patterns
- Test cases added
- Educational explanations
- Security best practices

## Honest Talking Points

### What to Emphasize:
- **AI-powered fixing** - Claude understands context
- **Comprehensive fixes** - Not just find/replace
- **Educational value** - Teaches secure coding
- **GitHub native** - Works with existing workflow
- **Test included** - Ensures fixes work

### What NOT to Promise:
- ~~Dashboard access~~ - Doesn't exist yet
- ~~Billing/pricing~~ - Not implemented
- ~~Email onboarding~~ - Not built
- ~~Usage metrics~~ - No tracking system
- ~~Free trial~~ - No payment system

## Recording Strategy

### Phase 1: Raw Recording (~45 minutes)
1. **Full introduction** explaining what RSOLV does
2. **Complete setup** showing workflow configuration
3. **Real-time scanning** with full logs
4. **Issue review** examining vulnerabilities found
5. **Fix generation** - let it run completely (10-15 min)
6. **PR examination** - detailed walkthrough
7. **Wrap-up** with honest next steps

### Phase 2: Editing (~12 minutes final)
- **Keep**: Key explanations, interesting logs, PR review
- **Speed up**: Long processing, repetitive sections
- **Cut**: Waiting time, errors/retries
- **Add**: Overlays explaining what's happening

## Backup Plans

### If Something Fails:
1. **API Key Issues**: Use hardcoded test key
2. **Scan Fails**: Show pre-existing issues
3. **Fix Generation Timeout**: Show previously generated PR
4. **Action Errors**: Explain this is early access

### Pre-Demo Testing:
```bash
# Run comprehensive test script
/home/dylan/dev/rsolv/demo-scripts/nodegoat-demo-test.sh

# Or use master demo script (interactive)
/home/dylan/dev/rsolv/demo-scripts/demo-master.sh

# Test specific issue trigger
gh issue edit 42 --repo RSOLV-dev/nodegoat-vulnerability-demo --add-label "rsolv:automate"
```

## Call to Action (Honest Version)

"RSOLV is in early access. We're working with select partners to refine
the technology. If you're interested in automated security fixes for your
codebase, reach out at [contact]. We'll provide you with an API key and
help you get started."

## What This Demo ACTUALLY Shows

1. **Real vulnerability detection** in actual code
2. **Automated issue creation** with detailed reports  
3. **AI-powered fix generation** using Claude
4. **High-quality PRs** with tests and education
5. **GitHub Actions integration** that works today

## What We DON'T Need to Fake

- The core technology works!
- Scanning finds real vulnerabilities
- Fixes are high quality
- Integration is smooth
- Value is clear

**Focus on what EXISTS and it's still a compelling demo!**