# RSOLV Workflow Templates

This directory contains workflow templates for deploying RSOLV security scanning to customer repositories.

## 🎯 Quick Start - Which Template to Use?

### ✅ Recommended: Simple Scan
**File**: `TEMPLATE-rsolv-simple-scan.yml`

Use this for most deployments:
- ✅ SCAN phase only (detect vulnerabilities)
- ✅ Fastest: ~1 minute runtime
- ✅ Simplest: Just add RSOLV_API_KEY
- ✅ Proven: Tested with 53 JS files (54s) and 146 Ruby files (1m4s)

**Best for**: Initial deployments, quick scans, CI/CD integration

### 🔥 Advanced: Full Pipeline
**File**: `TEMPLATE-rsolv-full-pipeline.yml`

Use this for comprehensive automation:
- ✅ SCAN → VALIDATE → MITIGATE pipeline
- ✅ Separate jobs with dependencies
- ✅ Configurable options (max_issues, create_prs)
- ✅ AI-powered fix generation

**Best for**: Mature deployments, automated remediation, security teams

### ⚠️ Deprecated: Docker-Based
**File**: `DEPRECATED-docker-based-workflow.yml`

**DO NOT USE** - Kept for reference only:
- ❌ Known git mounting issues
- ❌ VALIDATE/MITIGATE phases fail
- ❌ 10x slower than GitHub Action
- ❌ Failed in production testing

## 📊 Multi-Language Support - Proven

| Language | Test Framework | Files Tested | Vulnerabilities Found | Runtime | Status |
|----------|---------------|--------------|----------------------|---------|--------|
| JavaScript | Jest | 53 | 28 | 54s | ✅ Proven |
| Ruby | RSpec | 146 | 35 | 1m 4s | ✅ Proven |
| Python | pytest | - | - | - | Not tested (but supported) |
| TypeScript | Jest/Vitest | - | - | - | Supported |
| Go | Testing | - | - | - | Supported |

**Conclusion**: Multi-language capability proven with JavaScript and Ruby. The same GitHub Action works for all supported languages.

## 🚀 Deployment Instructions

### Option 1: Simple Scan (Recommended)

1. **Copy template** to customer repository:
   ```bash
   cp TEMPLATE-rsolv-simple-scan.yml .github/workflows/rsolv-security-scan.yml
   ```

2. **Add secret** in GitHub repository settings:
   - Name: `RSOLV_API_KEY`
   - Value: Customer's RSOLV API key

3. **Commit and push** - workflow runs automatically on push to main

### Option 2: Full Pipeline (Advanced)

1. **Copy template**:
   ```bash
   cp TEMPLATE-rsolv-full-pipeline.yml .github/workflows/rsolv-security-pipeline.yml
   ```

2. **Add secrets**:
   - `RSOLV_API_KEY`: For pattern fetching
   - `ANTHROPIC_API_KEY`: For AI-powered mitigation

3. **Commit and push**

## 📖 Template Documentation

### TEMPLATE-rsolv-simple-scan.yml

**Features**:
- Uses GitHub Action: `RSOLV-dev/rsolv-action@v3.7.47`
- SCAN mode only
- Creates GitHub Issues with `rsolv:detected` label
- Runs on: manual trigger + push to main

**Secrets required**:
- `RSOLV_API_KEY` (required)

**Permissions**:
- `contents: read` (read repository files)
- `issues: write` (create vulnerability issues)

**Expected output**:
- GitHub Issues for each vulnerability type
- Summary in workflow logs

### TEMPLATE-rsolv-full-pipeline.yml

**Features**:
- Three separate jobs: SCAN → VALIDATE → MITIGATE
- Job dependencies ensure proper ordering
- Configurable via workflow inputs
- Creates Pull Requests with fixes

**Secrets required**:
- `RSOLV_API_KEY` (required)
- `ANTHROPIC_API_KEY` (required for MITIGATE)

**Permissions**:
- `contents: write` (create branches, commits)
- `issues: write` (create/update issues)
- `pull-requests: write` (create PRs)

**Workflow inputs**:
- `max_issues`: Limit number of issues to process (default: 5)
- `create_prs`: Whether to create PRs with fixes (default: true)

## 🔍 Testing & Validation

All templates have been tested in Phase 4.2 of RFC-060:

### JavaScript/Jest (NodeGoat)
- **Repository**: RSOLV-dev/nodegoat-vulnerability-demo
- **Workflow Run**: [#18431970333](https://github.com/RSOLV-dev/nodegoat-vulnerability-demo/actions/runs/18431970333)
- **Results**: 53 files, 28 vulnerabilities, 54s runtime
- **Status**: ✅ Production-ready

### Ruby/RSpec (RailsGoat)
- **Repository**: RSOLV-dev/railsgoat
- **Workflow Run**: [#18422646855](https://github.com/RSOLV-dev/railsgoat/actions/runs/18422646855)
- **Results**: 146 files, 35 vulnerabilities, 1m 4s runtime
- **Status**: ✅ Production-ready

## 🎓 Architecture Decision: GitHub Action vs Docker

### Why GitHub Action Won

**GitHub Action Approach** (Current):
- ✅ Native git integration (no mounting issues)
- ✅ Faster: No Docker build step (~30s saved)
- ✅ Simpler: Less configuration required
- ✅ Reusable: Published action with version pinning
- ✅ All phases work: SCAN, VALIDATE, MITIGATE

**Docker Approach** (Deprecated):
- ❌ Git mounting problems (`.git` not accessible)
- ❌ VALIDATE phase fails: "fatal: not a git repository"
- ❌ MITIGATE phase fails: Cannot create branches/commits
- ❌ 10x slower: Docker build + execution overhead
- ⚠️ Only SCAN phase worked

### When to Use Docker (Rare Cases)

Docker approach may still be useful for:
- Air-gapped environments (no GitHub connectivity)
- Self-hosted runners with Docker-in-Docker
- Custom Docker base images required
- Enterprise environments with Docker mandates

If you need Docker approach, see `DEPRECATED-docker-based-workflow.yml` and address the git mounting issues first.

## 📝 Version History

- **v3.7.47**: Current recommended version (Phase 4.2 tested)
- **v3.7.35**: Latest published GitHub Release
- **v3.6.x**: Deprecated (has infinite loop bugs)

Always use v3.7.47 or later per template specifications.

## 🐛 Troubleshooting

### Workflow hangs or times out
- ✅ Ensure using v3.7.47+ (v3.6.x has bugs)
- ✅ Check RSOLV_API_KEY is set correctly
- ✅ Verify repository size (<1000 files for best performance)

### No issues created
- ✅ Check workflow logs for vulnerabilities found
- ✅ Verify `issues: write` permission is granted
- ✅ Check if issues already exist (won't duplicate)

### VALIDATE/MITIGATE phases fail
- ✅ Use GitHub Action templates (not Docker)
- ✅ Add ANTHROPIC_API_KEY for MITIGATE phase
- ✅ Ensure `contents: write` permission

## 📚 Related Documentation

- [RFC-060 Phase 4.2](../../docs/RFC-060-phase-4.2.md) - Testing methodology
- [RSOLV Action Documentation](https://github.com/RSOLV-dev/rsolv-action)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)

## ✅ Support

For issues or questions:
1. Check template inline documentation
2. Review workflow logs in GitHub Actions
3. Consult RSOLV-dev/rsolv-action repository
4. Contact RSOLV support team
