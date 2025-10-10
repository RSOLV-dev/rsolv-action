# RSOLV Workflow Deployment Guide

## Overview

This guide explains how to deploy RSOLV security scanning workflows to target repositories.

## Important: Where Workflows Should Run

**❌ WRONG:** Running workflows in the RSOLV-action repository that clone and scan other repos

**✅ CORRECT:** Deploying workflows directly IN the target repository being scanned

## Why This Matters

When a GitHub Actions workflow runs, it operates in the context of its repository. If you run a security scan workflow in the RSOLV-action repository:

- ❌ Scans BOTH RSOLV-action codebase AND target repo (1000+ files instead of ~25)
- ❌ Runtime increases from 5-10 minutes to 50+ minutes
- ❌ Creates spurious GitHub Issues in RSOLV-action instead of target repo
- ❌ Artifacts and results are stored in wrong repository
- ❌ PR comments and integration features won't work correctly

## Deployment Methods

### Method 1: Using GitHub Actions (Recommended)

Deploy workflows that use the published GitHub Action:

```yaml
name: RSOLV Security Scan

on:
  workflow_dispatch:
  push:
    branches: [main]

permissions:
  contents: write
  issues: write
  pull-requests: write

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: RSOLV Scan
        uses: RSOLV-dev/rsolv-action@v3.7.47  # IMPORTANT: Use v3.7.47+ (v3.6.x has bugs)
        with:
          rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
          mode: 'scan'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Advantages:**
- Simplest deployment
- Automatic updates when action is updated
- Official, supported method
- GitHub manages Action caching

**Example:** See `nodegoat-vulnerability-demo/.github/workflows/rsolv-security-scan.yml`

### Method 2: Using Docker (Advanced)

For development or when you need to test unreleased changes:

```yaml
name: RSOLV Security Scan (Docker)

on:
  workflow_dispatch:

permissions:
  contents: write
  issues: write

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      # Clone and build RSOLV-action
      - name: Clone RSOLV-action
        run: git clone --depth=1 https://github.com/RSOLV-dev/RSOLV-action.git rsolv-build

      - name: Setup Bun
        uses: oven-sh/setup-bun@v1

      - name: Build Docker image
        working-directory: rsolv-build
        run: |
          bun install
          docker build -t rsolv/action:latest .

      # Run scan on THIS repository
      - name: Run SCAN
        run: |
          docker run --rm \
            -v $(pwd):/workspace \
            -w /workspace \
            -e RSOLV_MODE=scan \
            -e GITHUB_WORKSPACE=/workspace \
            rsolv/action:latest
```

**Advantages:**
- Can test unreleased changes
- Full control over Docker image
- Useful for debugging

**Disadvantages:**
- Longer runtime (must build Docker image each time)
- More complex workflow
- Manual version management

**Templates Available:**
- `TEMPLATE-rsolv-simple-scan.yml` - Simple scan workflow (52 second runtime)  ✅ RECOMMENDED
- `TEMPLATE-rsolv-full-pipeline.yml` - Full 3-phase pipeline (scan/validate/mitigate)
- `TEMPLATE-rsolv-security-scan.yml` - Docker-based approach (for development)

## Demo Repository Examples

### nodegoat-vulnerability-demo (JavaScript)

**Repository:** https://github.com/RSOLV-dev/nodegoat-vulnerability-demo

**Workflows:**
- `rsolv-security-scan.yml` - Basic scan-only workflow
- `rsolv-three-phase-demo.yml` - Full SCAN → VALIDATE → MITIGATE demo
- `rsolv-automate-orchestrator.yml` - Automated continuous security

**Proven Performance (v3.7.47):**
- 53 JavaScript files scanned
- Runtime: 52 seconds total
- 28 vulnerabilities detected
- Scan phase: 7.9 seconds

### railsgoat (Ruby)

**Repository:** https://github.com/RSOLV-dev/railsgoat

**Expected setup:** Similar workflow structure to nodegoat, adapted for Ruby

## Deployment Steps

### For New Demo Repository

1. **Clone the demo repository:**
   ```bash
   git clone https://github.com/RSOLV-dev/[demo-repo].git
   cd [demo-repo]
   ```

2. **Create workflows directory:**
   ```bash
   mkdir -p .github/workflows
   ```

3. **Copy template workflow:**
   ```bash
   # For simple scan (recommended - 52 second runtime):
   cp /path/to/RSOLV-action/.github/workflows/TEMPLATE-rsolv-simple-scan.yml \
      .github/workflows/rsolv-security-scan.yml

   # OR for full pipeline:
   cp /path/to/RSOLV-action/.github/workflows/TEMPLATE-rsolv-full-pipeline.yml \
      .github/workflows/rsolv-full-pipeline.yml
   ```

4. **Configure secrets in GitHub:**
   - Go to Repository Settings → Secrets and variables → Actions
   - Add: `RSOLV_API_KEY` (or `ANTHROPIC_API_KEY` for Docker method)
   - `GITHUB_TOKEN` is automatically provided

5. **Commit and push:**
   ```bash
   git add .github/workflows/rsolv-security-scan.yml
   git commit -m "Add RSOLV security scan workflow"
   git push
   ```

6. **Test the workflow:**
   - Go to Actions tab in GitHub
   - Select "RSOLV Security Scan"
   - Click "Run workflow"

## Multi-Language Testing

To test RSOLV against multiple languages, deploy workflows to multiple demo repositories:

```yaml
# In your CI coordination repository (NOT in RSOLV-action!)
name: Multi-Language Security Test Coordinator

on:
  workflow_dispatch:

jobs:
  trigger-scans:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - repo: RSOLV-dev/nodegoat-vulnerability-demo
            workflow: rsolv-security-scan.yml
          - repo: RSOLV-dev/railsgoat
            workflow: rsolv-security-scan.yml
    steps:
      - name: Trigger workflow in target repo
        run: |
          gh workflow run ${{ matrix.workflow }} \
            --repo ${{ matrix.repo }}
        env:
          GH_TOKEN: ${{ secrets.GH_PAT }}
```

## Deprecated Workflows

### DEPRECATED-multi-language-security-scan.yml.txt

This workflow attempted to run multi-language testing FROM the RSOLV-action repository. It is deprecated because:

1. Scanned wrong files (RSOLV-action + demo repos)
2. Created issues in wrong repository
3. Excessive runtime (50+ minutes vs 5-10 minutes)
4. Violated principle of scanning in target repository context

**Do not use this workflow.** It is kept for reference only.

## Troubleshooting

### Issue: Workflow scans too many files

**Problem:** Workflow is scanning more than expected files (e.g., 1000+ instead of 25)

**Solution:** Ensure the workflow is deployed IN the target repository, not in RSOLV-action

### Issue: Issues created in wrong repository

**Problem:** GitHub Issues are created in RSOLV-action instead of target repo

**Solution:** The workflow must run in the target repository. Check which repo the workflow is deployed to.

### Issue: Long runtime (50+ minutes)

**Problem:** Scan takes much longer than expected

**Likely cause:** Workflow is scanning RSOLV-action codebase + target repo

**Solution:** Deploy workflow to target repository only

## Best Practices

1. **One workflow per repository**: Each demo/target repository should have its own workflow
2. **Use GitHub Action method**: Prefer `uses: RSOLV-dev/rsolv-action@VERSION` over Docker
3. **Version pinning**: Use v3.7.47 or later (v3.6.x has infinite loop bugs)
4. **Secret management**: Store API keys in GitHub Secrets, never commit them
5. **Limit scope**: Use `max_issues` parameter in demos to keep runtime reasonable
6. **Monitor execution**: Set up notifications for workflow failures

## References

- [RSOLV-action Repository](https://github.com/RSOLV-dev/RSOLV-action)
- [nodegoat Demo Workflows](https://github.com/RSOLV-dev/nodegoat-vulnerability-demo/tree/main/.github/workflows)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Docker Build Documentation](https://docs.docker.com/engine/reference/commandline/build/)

## Support

For issues or questions about workflow deployment:
1. Check existing workflows in demo repositories
2. Review this documentation
3. Open an issue in RSOLV-action repository

---

**Last Updated:** 2025-10-10
**Related RFC:** RFC-060 Phase 4.2
