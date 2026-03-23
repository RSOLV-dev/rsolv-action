# RSOLV: Test-First AI Security Fixes

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-RSOLV-blue.svg?colorA=24292e&colorB=0366d6&style=flat&longCache=true&logo=github)](https://github.com/marketplace/actions/rsolv-test-first-ai-security-fixes)

> Ship secure code faster. Every vulnerability proven with a failing test. Every fix validated by making it pass.

## Why RSOLV?

- **🔍 Proof, Not Warnings** — We generate a failing test that exploits each vulnerability. Run it yourself—if it fails, it's real. No more investigating scanner maybes.
- **✅ Fixes That Actually Work** — Our AI writes fixes that make the exploit test pass. Not "this should fix it"—proof the vulnerability is gone.
- **🛡️ Regression Protection Built In** — That exploit test stays in your codebase forever. The vulnerability can never return silently.
- **🔧 Your Tools, Your Framework** — Tests run in Jest, pytest, RSpec—whatever you already use. No new tooling to learn.

## Quick Start

### 1. Get Your API Key
- [Sign up at rsolv.dev/signup](https://rsolv.dev/signup)

### 2. Add API Key to GitHub Secrets
In your repository: Settings → Secrets → New repository secret
- Name: `RSOLV_API_KEY`
- Value: Your API key from step 1

### 3. Choose Your Workflow

**Recommended: Scan + Matrix Process** (Production workflow)

Two-job pipeline with per-issue isolation. The scan job detects vulnerabilities, then
a matrix strategy processes each issue independently -- one vulnerability per PR,
no scope leak between fixes.

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

- Each matrix cell gets a fresh `actions/checkout` -- no shared working directory
- One vulnerability per PR, no scope leak between fixes
- `fail-fast: false` ensures one failure does not block other fixes
- `max-parallel: 1` avoids branch conflicts (increase if your repo can handle concurrent PRs)
- `pipeline_run_id` connects scan results to each process step
- `issue_numbers` output drives the GitHub Actions matrix strategy

**Scan Only** (Assessment mode)

Run scan without processing fixes. Good for understanding your security posture first.

```yaml
name: RSOLV Security Scan

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 0 * * 0'
  workflow_dispatch:

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      issues: write

    steps:
      - uses: actions/checkout@v4

      - name: RSOLV Security Scan
        uses: RSOLV-dev/RSOLV-action@v4
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
          mode: 'scan'
```

**Legacy (deprecated): Full Pipeline**

> **Deprecated.** `mode: 'full'` runs all phases in a single job. It logs a deprecation
> warning at runtime. Use the scan+matrix pattern above instead for per-issue isolation
> and independent PRs.

```yaml
name: RSOLV Full Pipeline (deprecated)

on:
  push:
    branches: [main]

jobs:
  security:
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
          mode: 'full'  # deprecated -- use scan+matrix instead
```

## How It Works

RSOLV uses a three-phase test-first methodology:

1. **SCAN** - Detects vulnerabilities using 170+ security patterns with AST validation
2. **VALIDATE** - Generates executable RED tests that prove vulnerabilities exist
3. **MITIGATE** - Applies AI-generated fixes that make the tests pass

Every fix is proven with tests that fail before and pass after—no guesswork.

## Configuration Options

### Core Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `rsolvApiKey` | RSOLV API key (get at rsolv.dev/signup) | Yes | - |
| `mode` | Operation mode: `scan`, `process`, or `full` (deprecated) | No | `scan` |
| `pipeline_run_id` | Pipeline run ID from a prior scan step (required for `process` mode) | No | - |
| `issue_number` | Issue number to process (used with matrix strategy in `process` mode) | No | - |
| `github-token` | GitHub token (auto-provided by Actions) | No | `${{ github.token }}` |
| `max_issues` | Maximum issues to process per run | No | `1` |

### Advanced Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `enable_ast_validation` | Use AST validation to reduce false positives | `true` |
| `executable_tests` | Generate executable RED tests | `true` |
| `claude_max_turns` | Max Claude iterations for test generation | `5` |
| `enable_educational_pr` | Include security explanations in PRs | `true` |
| `api_url` | RSOLV API endpoint | `https://api.rsolv.dev` |

For complete configuration options, see [Documentation](https://docs.rsolv.dev).

## Security Features

### 170+ Security Patterns

Enterprise-grade vulnerability detection across 7 languages with OWASP Top 10 coverage:

- **Injection**: SQL, NoSQL, Command, LDAP, Template, XPath
- **XSS**: React dangerouslySetInnerHTML, innerHTML, document.write
- **Authentication**: JWT vulnerabilities, weak sessions, missing auth
- **Access Control**: Missing authorization, CSRF, unvalidated redirects
- **Cryptographic Failures**: Weak encryption, hardcoded secrets
- **Misconfiguration**: CORS, security headers, debug mode
- **Vulnerable Components**: Outdated dependencies, dangerous functions
- **SSRF**: Server-side request forgery with DNS rebinding protection

### Two-Layer Validation

**Layer 1: AST Analysis** filters the noise before you see it:
- Comment detection (filters out documentation)
- String literal analysis (ignores example code)
- Data flow analysis (validates reachability)

**Layer 2: Executable Proof** — every vulnerability that passes AST validation gets a generated exploit test. If the test doesn't fail, we don't report it.

Supported: JavaScript, TypeScript, Python, Ruby, Java, PHP, Elixir

## Pricing

- **Trial**: 5 credits free at signup, 5 more when you add billing
- **Pay As You Go**: $29 per fix
- **Pro**: $599/month (60 fixes included, then $15/fix for additional)

[View detailed pricing](https://rsolv.dev/pricing)

## Rate Limits

**AST Validation API:** 500 requests per hour per API key

This limit applies to vulnerability validation (computationally expensive). Other endpoints (pattern fetching, phase data) have generous limits. Weekly scheduled scans and manual runs work within these limits.

**Need higher limits?** Contact us at [support@rsolv.dev](mailto:support@rsolv.dev) for enterprise plans.

## Support & Documentation

- 📧 Email: [support@rsolv.dev](mailto:support@rsolv.dev)
- 📖 Docs: [docs.rsolv.dev](https://docs.rsolv.dev)
- 💬 GitHub Issues: [Report bugs or request features](https://github.com/RSOLV-dev/rsolv-action/issues)

## Troubleshooting

### Common Issues

#### Pull Request Creation Failures

If RSOLV fails to create a pull request:
1. Check that the workflow has `contents: write` and `pull-requests: write` permissions
2. Verify the GITHUB_TOKEN is properly configured
3. Check action logs for specific error messages

#### File Paths in Issues

Always use **relative paths** (not absolute) when creating issues:
- ✅ **Correct**: `app/data/allocations-dao.js`
- ❌ **Wrong**: `/app/data/allocations-dao.js`

GitHub Actions runs in a containerized environment where absolute paths may fail.

#### Timeout Issues

For complex vulnerabilities:
- Default timeout is 60 minutes
- Consider processing one issue at a time
- Use `mode: scan` first to assess scope

For more help, see [Documentation](https://docs.rsolv.dev) or [open an issue](https://github.com/RSOLV-dev/rsolv-action/issues).

## License

Copyright © 2026 RSOLV. All rights reserved.

This software is proprietary. See [LICENSE](LICENSE) for terms.

---

**Built by test-first engineers.** We write the failing test before the fix—in our own code, and now in yours.
