# RSOLV: Test-First AI Security Fixes

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-RSOLV-blue.svg?colorA=24292e&colorB=0366d6&style=flat&longCache=true&logo=github)](https://github.com/marketplace/actions/rsolv-test-first-ai-security-fixes)

> We prove it. The fix is on us. Every vulnerability confirmed with a failing test. Every fix validated by making it pass.

## Why RSOLV?

- **No Test, No Fix** — Every finding is backed by a behavioral test that fails. If VALIDATE can't prove it, MITIGATE doesn't touch it.
- **Fixes That Stick** — Fixes ship as PRs with the test that caught the vulnerability. It stays in your repo as a permanent regression guard.
- **Close Issues, Not Tabs** — No triage queue to review. No dashboard to check. Proven vulnerabilities get fix PRs. You merge or don't.
- **Works With What You Have** — GitHub Action, one workflow file. Sits alongside Snyk, Dependabot, or GHAS — adds proof and fixes to the candidates they find.

## Quick Start

### 1. Get Your API Key
- [Sign up at rsolv.dev/signup](https://rsolv.dev/signup)

### 2. Add API Key to GitHub Secrets
In your repository: Settings → Secrets → New repository secret
- Name: `RSOLV_API_KEY`
- Value: Your API key from step 1

### 3. Add the Workflow

Create `.github/workflows/rsolv-security.yml`:

```yaml
name: RSOLV Security Pipeline

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 0 * * 0'  # Weekly scan
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
      - uses: actions/checkout@v4
      - id: rsolv
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
      - uses: actions/checkout@v4
      - uses: RSOLV-dev/RSOLV-action@v4
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
          mode: 'process'
          pipeline_run_id: ${{ needs.scan.outputs.pipeline_run_id }}
          issue_number: ${{ matrix.issue_number }}
```

**Why this pattern?**

- Each matrix cell gets a fresh `actions/checkout` — no shared working directory
- One vulnerability per PR, no scope leak between fixes
- `fail-fast: false` ensures one failure does not block other fixes
- `max-parallel: 1` avoids branch conflicts (increase if your repo can handle concurrent PRs)

**Scan Only** (Assessment mode)

Run scan without processing fixes. Good for understanding your security posture first.

```yaml
- uses: RSOLV-dev/RSOLV-action@v4
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
    mode: 'scan'
```

## How It Works

Three phases. SCAN detects. VALIDATE proves it with a failing test. MITIGATE fixes it and makes the test pass.

1. **SCAN** — 183 security patterns across 7 languages. AST validation filters noise before you see it.
2. **VALIDATE** — Writes a behavioral test that exercises the actual code path and fails. If the test can't prove the vulnerability, no fix is attempted.
3. **MITIGATE** — Generates a fix that makes the failing test pass, then opens a PR with the fix, the test, and an educational explanation.

Every step produces an artifact you can inspect. No black boxes.

## Configuration

### Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `rsolvApiKey` | RSOLV API key ([get one here](https://rsolv.dev/signup)) | Yes | — |
| `mode` | `scan` or `process` | No | `scan` |
| `pipeline_run_id` | Pipeline run ID from scan step (required for `process` mode) | No | — |
| `issue_number` | Issue number to process (used with matrix strategy) | No | — |
| `max_issues` | Maximum issues to create per scan | No | `3` |
| `scan_output` | Where findings go: `issues` (default), `report` (artifact only) | No | `issues` |
| `enable_ast_validation` | AST validation to reduce false positives | No | `true` |
| `enable_educational_pr` | Include security explanations in PRs | No | `true` |
| `api_url` | RSOLV API endpoint (override for staging/enterprise) | No | `https://api.rsolv.dev` |

### Outputs

| Output | Description |
|--------|-------------|
| `pipeline_run_id` | Pipeline run ID for passing from scan to process jobs |
| `issue_numbers` | JSON array of issue numbers for matrix strategy (e.g. `[230,231,232]`) |
| `issues_created` | Count of GitHub issues created |
| `created_issues` | GitHub issues created (JSON array with full metadata) |
| `scan_results` | Scan results in JSON format |
| `has_issues` | Whether any issues were found |

### Scan Output Modes

By default, RSOLV creates GitHub issues for each finding (`scan_output: 'issues'`). This triggers the full validate/mitigate pipeline.

For **audit or discovery scans** where you want findings without creating issues, use report mode:

```yaml
- uses: RSOLV-dev/RSOLV-action@v4
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
    mode: 'scan'
    scan_output: 'report'
```

This uploads a structured JSON + markdown report as a workflow artifact — useful for security audits, compliance reviews, or evaluating RSOLV before enabling automated fixes.

## Security Coverage

### 183 Security Patterns across 7 Languages

OWASP Top 10 coverage for JavaScript, TypeScript, Python, Ruby, Java, PHP, and Elixir:

- **Injection** — SQL, NoSQL, Command, LDAP, Template, XPath
- **XSS** — DOM manipulation, unsafe HTML assignment, framework-specific patterns
- **Authentication** — JWT vulnerabilities, weak sessions, missing auth
- **Access Control** — Missing authorization, CSRF, unvalidated redirects
- **Cryptographic Failures** — Weak encryption, hardcoded secrets
- **Misconfiguration** — CORS, security headers, debug mode
- **Vulnerable Components** — Outdated dependencies, dangerous functions
- **SSRF** — Server-side request forgery with DNS rebinding protection

### Two-Layer Validation

**Layer 1: AST Analysis** filters the noise before you see it:
- Comment detection (filters out documentation)
- String literal analysis (ignores example code)
- Data flow analysis (validates reachability)

**Layer 2: Executable Proof** — every vulnerability that passes AST validation gets a generated exploit test. If the test can't prove the vulnerability, the issue is labeled inconclusive and no fix is attempted.

## What You Get in a PR

Each fix PR includes:
- The **fix** itself — minimal, targeted changes
- A **RED test** that fails without the fix and passes with it
- **Educational content** — what the vulnerability is, why it matters, and how the fix works
- **Validation context** — how the vulnerability was confirmed and what was tested
- **CWE and OWASP references** for compliance tracking

## Pricing

You pay when we prove it. Start free, no card required.

- **Free**: $0/month — 5 validations/month
- **Pro**: $49/month — 50 validations, 15 fixes/month ($10/additional fix)
- **Team**: $149/month — 150 validations, 50 fixes/month ($7/additional fix)

[View full pricing](https://rsolv.dev/pricing)

## Support

- Email: [support@rsolv.dev](mailto:support@rsolv.dev)
- Docs: [rsolv.dev/docs](https://rsolv.dev/docs)
- GitHub Issues: [Report bugs or request features](https://github.com/RSOLV-dev/RSOLV-action/issues)

## License

Copyright © 2026 RSOLV. All rights reserved.

This software is proprietary. See [LICENSE](LICENSE) for terms.

---

**Your scanner found 200 alerts. Which ones are real?** RSOLV proves vulnerabilities with a failing test before fixing them. Start free at [rsolv.dev/signup](https://rsolv.dev/signup).
