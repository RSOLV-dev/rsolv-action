# RFC-074: CLI Provisioning Tool

**Status**: Draft (Future Work - post RFC-064)
**Created**: 2025-10-20
**Timeline**: TBD
**Dependencies**: RFC-065 (Automated Customer Provisioning)

## Related RFCs

**Depends on:**
- RFC-065 (Automated Customer Provisioning) - API endpoint required

**Enables:**
- One-command setup for developers
- Framework-aware workflow generation
- Automated GitHub secret management

## Summary

Create a CLI tool (`npx rsolv init`) that automates RSOLV setup: signup, workflow installation, and GitHub secret configuration.

## Problem

Current setup requires:
1. Manual signup via web form
2. Copy/paste API key
3. Create workflow file manually
4. Add GitHub secret manually

**Too many manual steps** for developer-friendly tool.

## Proposed Solution

### CLI Tool Features
```bash
npx rsolv init

# Detects framework automatically
# Prompts for email/signup or login
# Generates workflow file
# Adds RSOLV_API_KEY to GitHub secrets (with permission)
# Runs first scan
```

### Auto-Detection
- Detect framework (Rails, Node.js, Django, etc.)
- Generate framework-specific workflow
- Customize fix validation tests

### GitHub Integration
- Use GitHub CLI (`gh`) for secret management
- Add `RSOLV_API_KEY` to repository secrets
- Optional: Create PR with workflow file

## Benefits

- **Fastest setup** - One command to start
- **Developer-friendly** - Matches modern tool UX
- **Less error-prone** - Automation reduces mistakes
- **Better onboarding** - First scan within minutes

## Technical Approach

**To be determined:**
- CLI framework (Commander.js, oclif, etc.)
- Framework detection logic
- GitHub CLI integration vs direct API
- Offline mode / manual key entry fallback

## Next Steps

1. Complete RFC-065 production deployment
2. Gather feedback on manual setup friction
3. Research framework detection strategies
4. Create detailed implementation plan
