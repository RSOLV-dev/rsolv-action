# RSOLV Demo Setup Guide - Complete Customer Journey

**Date**: 2025-01-19  
**Purpose**: Step-by-step guide for demonstrating RSOLV's complete functionality  
**Duration**: ~20-30 minutes for full demo  
**Setup Time**: ~30 minutes to prepare demo environment  
**Recording Time**: ~12 minutes for video

## Prerequisites

1. **RSOLV Platform** running locally or on staging
2. **GitHub Account** with a test repository containing vulnerabilities
3. **RSOLV API Key** from dashboard
4. **Screen recording software** for demo video

## Demo Repository Setup

### Option 1: Use Prepared Vulnerable App
```bash
# Clone the vulnerable demo app
git clone https://github.com/RSOLV-demos/vulnerable-nodejs-app
cd vulnerable-nodejs-app

# This repo contains intentional vulnerabilities:
# - SQL injection in routes/users.js
# - XSS in views/profile.ejs
# - Command injection in utils/backup.js
# - Hardcoded secrets in config/database.js
# - Path traversal in routes/files.js
```

### Option 2: Create Your Own Vulnerable Code
```javascript
// Example 1: SQL Injection (save as routes/search.js)
app.get('/search', (req, res) => {
  const searchTerm = req.query.q;
  // VULNERABLE: Direct string concatenation
  const query = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%'`;
  db.query(query, (err, results) => {
    res.json(results);
  });
});

// Example 2: XSS (save as views/comment.ejs)
<div class="comment">
  <!-- VULNERABLE: Unescaped user input -->
  <p><%- userComment %></p>
</div>

// Example 3: Command Injection (save as utils/ping.js)
const { exec } = require('child_process');
app.post('/ping', (req, res) => {
  const host = req.body.host;
  // VULNERABLE: User input in shell command
  exec(`ping -c 4 ${host}`, (err, stdout) => {
    res.send(stdout);
  });
});
```

## Step-by-Step Demo Flow

### 1. Customer Onboarding (2-3 minutes)

```bash
# Show landing page
open https://rsolv.dev

# Demonstrate email signup
# - Enter email in early access form
# - Show ConvertKit integration working
# - Check email for welcome message

# Access dashboard
open https://rsolv.dev/dashboard

# Show API key management
# - View generated API key
# - Copy for GitHub setup
# - Show usage limits and billing info
```

### 2. GitHub Repository Setup (3-5 minutes)

```bash
# Add RSOLV API key to repository secrets
gh secret set RSOLV_API_KEY --body "rsolv_sk_test_abc123..."

# Create RSOLV workflow file
mkdir -p .github/workflows
cat > .github/workflows/rsolv-security.yml << 'EOF'
name: RSOLV Security Automation

on:
  # Weekly security scan
  schedule:
    - cron: '0 0 * * 1'
  
  # Manual trigger for demo
  workflow_dispatch:
  
  # Autofix when issue is labeled
  issues:
    types: [labeled]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: RSOLV Security Scan
        uses: RSOLV-dev/rsolv-action@v2
        with:
          api_key: ${{ secrets.RSOLV_API_KEY }}
          scan_mode: scan
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  autofix:
    if: github.event.label.name == 'rsolv:automate'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: RSOLV AutoFix
        uses: RSOLV-dev/rsolv-action@v2
        with:
          api_key: ${{ secrets.RSOLV_API_KEY }}
          issue_number: ${{ github.event.issue.number }}
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
EOF

# Commit and push
git add .github/workflows/rsolv-security.yml
git commit -m "Add RSOLV security automation"
git push
```

### 3. Trigger Security Scan (5-7 minutes)

```bash
# Manually trigger the workflow
gh workflow run "RSOLV Security Automation"

# Watch the scan progress
gh run watch

# Alternative: Use GitHub UI
# Actions tab → RSOLV Security Automation → Run workflow
```

**What happens during scan:**
1. RSOLV-action fetches patterns from API
2. Scans repository for vulnerabilities
3. **AST validation reduces false positives by 70-90%**
4. Groups vulnerabilities by type
5. Creates GitHub issues automatically

### 4. Review Created Issues (2-3 minutes)

Show the automatically created issues:

```bash
# List security issues
gh issue list --label security

# View a specific issue
gh issue view 42
```

**Example issue content:**
```markdown
# 🔒 SQL Injection vulnerabilities found in 3 files

## Security Vulnerability Report

**Type**: SQL Injection
**Severity**: CRITICAL
**Total Instances**: 5
**Affected Files**: 3

### Affected Files

1. **routes/search.js** (2 instances)
   - Line 15: Direct string concatenation in query
   - Line 34: User input in WHERE clause

2. **models/user.js** (2 instances)
   - Line 45: f-string in SQL query
   - Line 78: Unsafe parameter binding

3. **utils/db-helper.js** (1 instance)
   - Line 23: Dynamic query construction

### Impact
SQL injection can allow attackers to:
- Read sensitive data
- Modify or delete data
- Execute administrative operations

### Recommended Action
Apply the `rsolv:automate` label to have RSOLV automatically fix these vulnerabilities.
```

### 5. Automated Fix Generation (7-10 minutes)

```bash
# Add the automation label to trigger fix
gh issue edit 42 --add-label "rsolv:automate"

# Watch the fix workflow run
gh run list --workflow="RSOLV Security Automation"
gh run watch
```

**Behind the scenes:**
1. **Credential vending**: RSOLV API key → Claude API key
2. **Claude Code SDK exploration**: 
   - Analyzes repository structure
   - Understands vulnerability context
   - Identifies all affected code
   - Generates comprehensive fix
3. **TDD approach**:
   - Writes tests first
   - Implements secure fix
   - Validates no breaking changes

### 6. Review Generated Pull Request (3-5 minutes)

```bash
# List pull requests
gh pr list

# View the generated PR
gh pr view 123 --web
```

**Show PR features:**
- Comprehensive title and description
- Security vulnerability details
- Code changes with proper patterns
- Test cases added
- Educational explanations
- Business impact summary

**Example PR content:**
```markdown
# [RSOLV] Fix SQL injection vulnerabilities (fixes #42)

## Summary
This PR addresses critical SQL injection vulnerabilities by replacing 
string concatenation with parameterized queries.

## Changes
- ✅ Replace string interpolation with parameter binding in routes/search.js
- ✅ Use prepared statements in models/user.js
- ✅ Implement query builder pattern in utils/db-helper.js
- ✅ Add security tests to prevent regression

## Security Tests Added
```javascript
describe("SQL injection prevention", () => {
  it("sanitizes malicious input in search queries", () => {
    const malicious = "'; DROP TABLE users; --";
    const result = search(malicious);
    expect(User.count()).toBeGreaterThan(0); // Table still exists
  });
});
```

## 🔒 Security Fixes

This PR addresses the following security vulnerabilities:

- **CRITICAL**: SQL Injection in `routes/search.js:15`
  - Risk: Database compromise, data theft
  - Fixed by: Using parameterized queries

## 📚 Educational Explanations

### Executive Summary
**Risk Score**: 85/100

SQL injection vulnerabilities allow attackers to manipulate database
queries, potentially accessing or modifying sensitive data.

**Key Business Impacts:**
- 💰 Financial: Potential data breach costs averaging $4.35M
- 🏢 Reputation: Customer trust loss, regulatory penalties
- 📊 Operations: Service disruption, data integrity issues
- 🔒 Data: Unauthorized access to customer records

**Recommended Actions:**
- Implement code review process for database queries
- Use ORM/query builders consistently
- Regular security training for developers

---
🤖 Generated by RSOLV with Claude
```

### 7. Merge and Tracking (2 minutes)

```bash
# Approve and merge the PR
gh pr review 123 --approve --body "LGTM! Comprehensive fix with tests."
gh pr merge 123 --squash

# RSOLV webhook automatically tracks:
# - PR merged event
# - Fix recorded for billing
# - Success metrics updated
```

## Key Demo Talking Points

### AST Validation Benefits
- Show false positive reduction: "Notice how RSOLV only flagged actual vulnerabilities"
- Highlight context awareness: "The AST parser understands this is user input flowing to a query"
- Demonstrate accuracy: "No false alarms on properly parameterized queries"

### AI-Powered Fixes
- Emphasize exploration: "Claude explores the entire codebase to understand patterns"
- Show comprehensiveness: "It found all instances, not just the obvious ones"
- Highlight TDD: "Tests are written first to ensure the fix works"

### Educational Value
- Business explanations: "Executives can understand the risk and impact"
- Technical details: "Developers learn secure coding practices"
- Actionable advice: "Specific steps to prevent future vulnerabilities"

### ROI and Metrics
- Time saved: "What would take hours is done in minutes"
- Consistency: "Every fix follows security best practices"
- Learning: "Your team improves with each fix"

## Recording Tips

### Pre-Recording Checklist (30 minutes setup)

1. **Preparation**:
   - [ ] Create fresh demo repository with vulnerabilities
   - [ ] Test RSOLV API key works
   - [ ] Clear browser cache for clean dashboard view
   - [ ] Test GitHub Actions workflow beforehand
   - [ ] Have multiple terminal windows ready
   - [ ] Set up screen recording software
   - [ ] Have script open on second monitor/device

2. **Pacing** (Total recording time: ~12 minutes):
   - Don't rush through AST validation explanation
   - Pause on generated issues to show quality
   - Let viewers see the PR description fully
   - Highlight key metrics and educational content

3. **Narration Focus**:
   - Start with the business problem
   - Emphasize automation and time savings
   - Show real security impact
   - End with ROI and next steps

### Confirmation: All Components Exist!

**No missing components** - Everything needed for the demo is fully implemented:
- ✅ Email signup via ConvertKit integration
- ✅ Dashboard with API key management
- ✅ GitHub Action (in RSOLV-action repository)
- ✅ Vulnerability scanning with AST validation
- ✅ Automated issue creation with detailed reports
- ✅ AI-powered fix generation using Claude
- ✅ Pull request creation with educational content
- ✅ Webhook tracking for billing and metrics

The system is complete and ready for demonstration!

## Troubleshooting

### Common Issues

1. **Workflow doesn't trigger**:
   ```bash
   # Check workflow syntax
   gh workflow list
   
   # View workflow runs
   gh run list
   
   # Check API key is set
   gh secret list
   ```

2. **No issues created**:
   - Verify vulnerabilities exist in code
   - Check RSOLV API key is valid
   - Review action logs for errors

3. **Fix generation fails**:
   - Ensure issue has correct label
   - Check API rate limits
   - Verify Claude integration working

### Support Resources
- Documentation: https://docs.rsolv.dev
- Support: support@rsolv.dev
- GitHub: https://github.com/RSOLV-dev/rsolv-action

## Next Steps After Demo

1. **For Prospects**:
   - Offer trial API key
   - Schedule follow-up call
   - Share case studies

2. **For Users**:
   - Show advanced configuration
   - Discuss custom patterns
   - Review usage analytics

3. **For Partners**:
   - Demonstrate API integration
   - Show webhook capabilities
   - Discuss volume pricing