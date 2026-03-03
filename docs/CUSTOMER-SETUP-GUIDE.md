# RSOLV Customer Setup Guide

This guide will walk you through setting up RSOLV to automatically find and fix security vulnerabilities in your GitHub repositories.

## Prerequisites

- A GitHub repository you want to protect
- Admin access to add secrets and workflows to your repository
- An RSOLV API key (get yours at https://rsolv.dev)

## Quick Start (2 minutes)

### Step 1: Add Your RSOLV API Key

1. Go to your repository on GitHub
2. Click **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Name: `RSOLV_API_KEY`
5. Value: Your RSOLV API key (starts with `rsolv_`)
6. Click **Add secret**

### Step 2: Create the Workflow

Create a single workflow file at `.github/workflows/rsolv-security.yml` that handles
both scanning and fixing:

```yaml
name: RSOLV Security Pipeline

on:
  # Run on every push to main branch
  push:
    branches: [ main ]
  # Run weekly on Mondays at 9 AM
  schedule:
    - cron: '0 9 * * 1'
  # Allow manual runs
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    outputs:
      pipeline_run_id: ${{ steps.rsolv.outputs.pipeline_run_id }}
      issue_numbers: ${{ steps.rsolv.outputs.issue_numbers }}
    permissions:
      contents: write
      issues: write
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Run RSOLV Security Scan
        id: rsolv
        uses: RSOLV-dev/RSOLV-action@v4
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
          mode: 'scan'
          max_issues: '3'

  process:
    needs: scan
    if: needs.scan.outputs.issue_numbers != '[]'
    strategy:
      matrix:
        issue_number: ${{ fromJSON(needs.scan.outputs.issue_numbers) }}
      fail-fast: false
      max-parallel: 1
    runs-on: ubuntu-latest
    permissions:
      contents: write
      issues: write
      pull-requests: write
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Process vulnerability fix
        uses: RSOLV-dev/RSOLV-action@v4
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
          mode: 'process'
          pipeline_run_id: ${{ needs.scan.outputs.pipeline_run_id }}
          issue_number: ${{ matrix.issue_number }}
```

This single workflow handles both scanning and fixing. The scan job detects
vulnerabilities, then the process job handles each one independently using
GitHub Actions matrix strategy -- one vulnerability per PR, no scope leak.

## How It Works

### 1. SCAN Phase -- Finding Vulnerabilities
- RSOLV scans your codebase using 170+ security patterns with AST validation
- Detects OWASP Top 10 vulnerabilities, CVEs, and framework-specific issues
- Groups similar vulnerabilities to avoid issue spam
- Outputs `pipeline_run_id` and `issue_numbers` for the process step

### 2. VALIDATE Phase -- Proving Vulnerabilities Exist
- For each issue, RSOLV generates an executable RED test that exploits the vulnerability
- If the test does not fail, the vulnerability is not reported (false positive filtering)
- Test frameworks: Jest, pytest, RSpec, ExUnit -- whatever your project already uses

### 3. MITIGATE Phase -- Applying Fixes
- AI generates a fix that makes the RED test pass (GREEN)
- Creates one pull request per vulnerability
- Each PR includes:
  - Detailed explanation of the vulnerability
  - The fix implementation with the proving test
  - Educational content about why this fix works
  - Compliance mapping (SOC2, PCI-DSS, etc.)

## Configuration Options

### Basic Configuration

Create `.github/rsolv.yml` for custom settings:

```yaml
# Security analysis settings
security:
  enableAnalysis: true
  scanDependencies: true
  includeEducationalContent: true
  
# AI provider settings  
aiProvider:
  provider: anthropic  # or openai, ollama
  model: claude-sonnet-4-5-20250929
  temperature: 0.2
  
# Issue creation settings
issues:
  groupSimilar: true
  maxIssuesPerRun: 10
  labels:
    - rsolv:automate
    - security
```

### Advanced: Scan Specific Paths

```yaml
# Only scan certain directories
scanPaths:
  include:
    - src/
    - lib/
    - app/
  exclude:
    - test/
    - node_modules/
    - vendor/
```

### Advanced: Custom Fix Behavior

```yaml
# Fix generation settings
fixes:
  createDraftPR: false  # Create PRs as drafts
  branchPrefix: "rsolv/fix-"
  commitPrefix: "fix(security): "
  includeTests: true
  educational:
    enabled: true
    verbosity: detailed  # basic, detailed, or comprehensive
```

## API Access

Your API key provides access to our complete pattern library:

- **With API Key**: All 172 security patterns across 6 languages and frameworks
- **Demo Mode**: ~20 basic patterns for evaluation (no API key required)

All paying customers receive access to the complete pattern library with no tiers or restrictions.

## Monitoring Usage

### View Scan Results
1. Check the **Actions** tab for workflow runs
2. Look for created issues in the **Issues** tab
3. Review pull requests in the **Pull requests** tab

### Usage Tracking
- View your usage at https://rsolv.dev/dashboard
- Set up webhooks for real-time notifications
- Export reports for compliance

## Best Practices

1. **Start with Scanning**
   - Run a manual scan first to understand your security posture
   - Review created issues before enabling automatic fixes

2. **Gradual Rollout**
   - Start with one repository
   - Fine-tune settings based on results
   - Expand to more repositories

3. **Review Process**
   - Always review generated PRs before merging
   - Use the educational content to train your team
   - Track metrics to show security improvements

## Troubleshooting

### No issues created after scan
- Check workflow logs for errors
- Verify API key is valid
- Ensure repository has vulnerabilities (try our demo patterns)

### Process job not running
- Verify the scan job found issues (check `issue_numbers` output is not `[]`)
- Check workflow permissions (`contents: write`, `issues: write`, `pull-requests: write`)
- Ensure API key is valid and active

### API key errors
- Keys should start with `rsolv_`
- Check key hasn't expired
- Verify API key is active and valid

## Educational Content

RSOLV includes educational content with every fix:

1. **Vulnerability Explanation**: What the issue is and why it matters
2. **Attack Scenarios**: How this could be exploited
3. **Fix Rationale**: Why this specific fix works
4. **Best Practices**: How to prevent similar issues
5. **Compliance Mapping**: Related compliance requirements (SOC2, PCI-DSS, etc.)

## Support

- Documentation: https://docs.rsolv.dev
- Support: support@rsolv.dev
- Status: https://status.rsolv.dev

---

## Example: Complete Setup in Action

Here's what happens when you set up RSOLV:

1. **Initial Scan** (Monday 9 AM)
   ```
   Found 12 vulnerabilities:
   - 2 SQL Injection (HIGH)
   - 3 XSS (MEDIUM)
   - 7 Hardcoded Secrets (HIGH)
   ```

2. **Issues Created**
   ```
   Issue #45: 🔒 SQL Injection vulnerabilities in 2 files
   Issue #46: 🔒 XSS vulnerabilities in 3 files  
   Issue #47: 🔒 Hardcoded secrets in 7 files
   ```

3. **Fixes Generated**
   ```
   PR #48: fix(security): Parameterize SQL queries
   PR #49: fix(security): Sanitize user input for XSS prevention
   PR #50: fix(security): Move secrets to environment variables
   ```

4. **Educational Content Included**
   Each PR includes explanations like:
   - "SQL injection occurs when user input is concatenated into queries..."
   - "This fix uses parameterized queries which separate data from code..."
   - "For SOC2 compliance, this addresses CC6.1 control requirements..."

Start protecting your code today! 🛡️