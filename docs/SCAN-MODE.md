# RSOLV Proactive Security Scanning

RSOLV can now proactively scan your repository for security vulnerabilities and automatically create issues for discovered problems. This enables a complete find-and-fix workflow.

## How It Works

1. **Scan**: RSOLV scans your entire repository for security vulnerabilities using 170+ patterns with AST validation
2. **Issue Creation**: Vulnerabilities are grouped by type and GitHub issues are created
3. **Process**: Each issue is processed independently -- VALIDATE generates a RED test, MITIGATE applies the fix

## Usage

### Recommended: Scan + Matrix Process

The recommended workflow uses a two-job pipeline with GitHub Actions matrix strategy.
Each issue is processed in isolation with a fresh checkout -- one vulnerability per PR,
no scope leak between fixes.

```yaml
name: RSOLV Security Pipeline

on:
  schedule:
    - cron: '0 0 * * 1'  # Weekly on Mondays
  push:
    branches: [main]
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

      - name: Run Security Scan
        id: rsolv
        uses: RSOLV-dev/RSOLV-action@v4
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
          mode: 'scan'
          max_issues: '3'

      - name: Display Results
        run: |
          echo "Pipeline run: ${{ steps.rsolv.outputs.pipeline_run_id }}"
          echo "Issues found: ${{ steps.rsolv.outputs.issue_numbers }}"

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

### Scan Only

Use scan mode alone to assess your security posture without applying fixes:

```yaml
name: RSOLV Security Scan

on:
  schedule:
    - cron: '0 0 * * 1'
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      issues: write
    steps:
      - uses: actions/checkout@v4

      - name: Run Security Scan
        id: rsolv
        uses: RSOLV-dev/RSOLV-action@v4
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
          mode: 'scan'
```

## Configuration Options

### Action Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `rsolvApiKey` | Your RSOLV API key | Yes | - |
| `mode` | `scan`, `process`, or `full` (deprecated) | No | `scan` |
| `pipeline_run_id` | Pipeline run ID from a prior scan step (required for `process`) | No | - |
| `issue_number` | Issue number to process (used with matrix strategy) | No | - |
| `max_issues` | Maximum issues to process per scan run | No | `1` |

### Outputs

When in scan mode:
- `pipeline_run_id`: Unique identifier connecting scan results to process steps
- `issue_numbers`: JSON array of issue numbers (e.g., `[42, 43, 45]`) for use with `fromJSON()` in matrix strategy
- `scan_results`: JSON object containing all discovered vulnerabilities
- `created_issues`: Array of GitHub issues created from the scan

## Supported Vulnerabilities

RSOLV scans for 170+ security patterns across 6 languages:

### Languages
- JavaScript/TypeScript
- Python
- Ruby
- Java
- PHP
- Elixir

### Vulnerability Types
- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal
- Weak Cryptography
- Hardcoded Secrets
- Insecure Random Number Generation
- XML External Entity (XXE)
- Server-Side Request Forgery (SSRF)
- And many more...

## Best Practices

1. **Regular Scanning**: Set up a weekly or monthly schedule
2. **Review Before Fixing**: Always review created issues before running fix mode
3. **Gradual Rollout**: Start with a small repository to understand the process
4. **Custom Labels**: Use custom labels to organize security issues

## Example: Testing with NodeGoat

NodeGoat is OWASP's deliberately vulnerable Node.js application, perfect for testing:

```yaml
name: Test RSOLV with NodeGoat

on:
  workflow_dispatch:

jobs:
  test-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      issues: write
    steps:
      - name: Checkout NodeGoat
        uses: actions/checkout@v4
        with:
          repository: OWASP/NodeGoat

      - name: Run RSOLV Scan
        uses: RSOLV-dev/RSOLV-action@v4
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
          mode: 'scan'
```

## Limitations

- Pattern matching uses 170+ regex-based patterns with AST validation for false positive filtering
- Large repositories may take several minutes to scan
- Binary files and files over 1MB are skipped

## Security Considerations

- Issues created contain vulnerability details but not exploit code
- Sensitive findings (like hardcoded secrets) are masked in issue descriptions
- All created issues are labeled for easy identification
- Review created issues before running fix mode in production