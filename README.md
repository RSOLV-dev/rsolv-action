# RSOLV: Test-First AI Security Fixes

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-RSOLV-blue.svg?colorA=24292e&colorB=0366d6&style=flat&longCache=true&logo=github)](https://github.com/marketplace/actions/rsolv-test-first-ai-security-fixes)

> Ship secure code faster. Test-first AI security that validates vulnerabilities with executable RED tests before fixing them. No guesswork—every fix is proven.

## Why RSOLV?

- **🔍 Real Vulnerabilities Only** - Built by test-driven engineers who hate false positives as much as you do. AST validation catches real issues, not regex noise
- **✅ Proof, Not Guesses** - Generates RED tests that prove vulnerabilities before fixing
- **🔧 Production-Ready Fixes** - AI-generated fixes that pass your existing test suite
- **📊 Framework-Native Tests** - Integrates with RSpec, Jest, pytest—your tools, your style
- **🚀 Complete Automation** - From detection to PR, fully automated in GitHub Actions

## Quick Start

### 1. Get Your API Key
- [Sign up at rsolv.dev/signup](https://rsolv.dev/signup) - Get 10 free credits to start

### 2. Add API Key to GitHub Secrets
In your repository: Settings → Secrets → New repository secret
- Name: `RSOLV_API_KEY`
- Value: Your API key from step 1

### 3. Choose Your Workflow

**Option A: Simple Scan** (Recommended for first-time users)

Detects vulnerabilities and creates GitHub issues. Perfect for getting started.

Create `.github/workflows/rsolv-security.yml`:

```yaml
name: RSOLV Security

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 0 * * 0'  # Weekly scan

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      issues: write
      pull-requests: write

    steps:
      - uses: actions/checkout@v4

      - name: RSOLV Security Scan
        uses: RSOLV-dev/rsolv-action@v3
        with:
          rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
          mode: 'scan'  # Start with scan only (recommended)
```

**Option B: Full Pipeline** (Advanced - better control)

Separate jobs for scan, validate, and fix phases with dependencies.

```yaml
name: RSOLV Full Pipeline

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 0 * * 0'

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      issues: write
    steps:
      - uses: actions/checkout@v4
      - uses: RSOLV-dev/rsolv-action@v3
        with:
          rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
          mode: 'scan'

  validate:
    needs: scan
    runs-on: ubuntu-latest
    permissions:
      contents: write
      issues: write
    steps:
      - uses: actions/checkout@v4
      - uses: RSOLV-dev/rsolv-action@v3
        with:
          rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
          mode: 'validate'

  mitigate:
    needs: validate
    runs-on: ubuntu-latest
    permissions:
      contents: write
      issues: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: RSOLV-dev/rsolv-action@v3
        with:
          rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
          mode: 'mitigate'
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
| `mode` | Operation mode: `scan`, `validate`, `mitigate`, or `full` | No | `scan` |
| `github-token` | GitHub token (auto-provided by Actions) | No | `${{ github.token }}` |
| `max_issues` | Maximum issues to process per run | No | `1` |

### Advanced Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `enable_ast_validation` | Use AST validation to reduce false positives | `true` |
| `executable_tests` | Generate executable RED tests (RFC-060) | `true` |
| `claude_max_turns` | Max Claude iterations for test generation | `5` |
| `enable_educational_pr` | Include security explanations in PRs | `true` |
| `api_url` | RSOLV API endpoint | `https://api.rsolv.dev` |

For complete configuration options, see [Configuration Guide](docs/CONFIGURATION.md).

## Security Features

### 170+ Security Patterns

Enterprise-grade vulnerability detection across 8 languages with OWASP Top 10 coverage:

- **Injection**: SQL, NoSQL, Command, LDAP, Template, XPath
- **XSS**: React dangerouslySetInnerHTML, innerHTML, document.write
- **Authentication**: JWT vulnerabilities, weak sessions, missing auth
- **Access Control**: Missing authorization, CSRF, unvalidated redirects
- **Cryptographic Failures**: Weak encryption, hardcoded secrets
- **Misconfiguration**: CORS, security headers, debug mode
- **Vulnerable Components**: Outdated dependencies, dangerous functions
- **SSRF**: Server-side request forgery with DNS rebinding protection

### AST-Based Validation

Reduces false positives by 70-90% through:
- Comment detection (filters out documentation)
- String literal analysis (ignores example code)
- User input flow analysis (validates reachability)
- Multi-language support (JavaScript, TypeScript, Python, Ruby, PHP, Java)

## Pricing

Based on RFC-066 credit system:

- **Trial**: 10 credits free (5 at signup + 5 when adding billing)
- **Pay As You Go**: $29 per fix
- **Pro**: $599/month (60 fixes included, then $15/fix for additional)

[View detailed pricing](https://rsolv.dev/pricing)

## Rate Limits

**AST Validation API:** 500 requests per hour per API key

This limit applies to vulnerability validation (computationally expensive). Other endpoints (pattern fetching, phase data) have generous limits. Weekly scheduled scans and manual runs work within these limits.

**Need higher limits?** Contact us at [support@rsolv.dev](mailto:support@rsolv.dev) for enterprise plans.

## External Issue Trackers

RSOLV supports multiple issue tracking platforms:

### Jira Integration

```yaml
- uses: RSOLV-dev/rsolv-action@v3
  with:
    rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
    jira_host: 'your-domain.atlassian.net'
    jira_email: 'your-email@example.com'
    jira_api_token: ${{ secrets.JIRA_API_TOKEN }}
```

See [Jira Integration Guide](docs/jira-integration.md) for details.

### Linear Integration

```yaml
- uses: RSOLV-dev/rsolv-action@v3
  with:
    rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
  env:
    LINEAR_API_KEY: ${{ secrets.LINEAR_API_KEY }}
```

See [Linear Integration Guide](docs/linear-integration.md) for details.

## Support & Documentation

- 📧 Email: [support@rsolv.dev](mailto:support@rsolv.dev)
- 📖 Docs: [docs.rsolv.dev](https://docs.rsolv.dev)
- 💬 GitHub Issues: [Report bugs or request features](https://github.com/RSOLV-dev/rsolv-action/issues)
- 📚 Examples: [See RSOLV in action](https://github.com/RSOLV-dev/examples)

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

For more troubleshooting, see [Troubleshooting Guide](docs/TROUBLESHOOTING.md).

## Development

### Prerequisites

- [Bun](https://bun.sh/) (latest version)
- Docker (for container testing)
- RSOLV-platform running locally

### Setup

```bash
# Clone the repository
git clone https://github.com/RSOLV-dev/rsolv-action.git
cd rsolv-action

# Install dependencies
bun install

# Run tests
bun test

# Type check
bun run typecheck

# Lint
bun run lint
```

See [Development Guide](docs/DEVELOPMENT.md) for complete setup instructions.

## License

Copyright © 2025 RSOLV. All rights reserved.

This software is proprietary. See [LICENSE](LICENSE) for terms.

---

**Built with ❤️ by developers who hate false positives**
