# GitHub Marketplace Submission Checklist

**RFC**: RFC-067 Week 2
**Date**: 2025-10-26
**Status**: Ready for submission

## Pre-Submission Verification

### Required Assets ✅
- [x] **action.yml** - Updated with marketplace metadata
- [x] **README.md** - Marketing-focused, marketplace-ready
- [x] **LICENSE** - Proprietary license documented
- [ ] **logo.png** - 500x500px, shield icon, blue color scheme
- [ ] **Screenshots** - Action in scan/validate/mitigate modes
- [x] **Support email** - support@rsolv.dev (verified working)
- [ ] **Documentation site** - docs.rsolv.dev (DNS pending)

### Technical Validation ✅
- [x] action.yml syntax validated
- [x] Workflow templates tested
- [x] Default mode set to 'scan' (prevents credit burn)
- [x] github-token auto-default configured
- [x] rsolvApiKey marked as required

## Submission Process

**Important**: GitHub Actions are published through the **release** process, not a separate submission form.

### Step 1: Navigate to Repository
**URL**: https://github.com/RSOLV-dev/RSOLV-action

### Step 2: Draft a Release
1. Click "Releases" in the right sidebar
2. Click "Draft a new release"
3. Check "Publish this Action to the GitHub Marketplace"
4. Accept the GitHub Marketplace Developer Agreement (if first time)

**Prerequisites**:
- Two-factor authentication enabled
- Repository is public
- `action.yml` exists at repository root
- No workflow files in the repository

### Step 3: Select Categories
- **Primary category**: Security
- **Secondary category** (optional): Code Quality, CI/CD

### Step 4: Release Details

**Choose a tag**: `v1.0.0` (semantic versioning)
**Release title**: `RSOLV v1.0.0 - Initial Marketplace Launch`
**Description**: Use content from LAUNCH-BLOG-POST.md (abbreviated for release notes)

### Step 5: Marketing Assets (Optional but Recommended)

**Logo**:
- Upload `logo.png` (500x500px)
- Shield icon, blue color scheme

**Screenshots** (3-5 recommended):
1. Action running in scan mode (detecting vulnerabilities)
2. Action running in validate mode (generating RED test)
3. Action running in mitigate mode (creating PR with fix)
4. Example pull request with educational security content
5. GitHub Actions workflow summary view

**Detailed Description** (supports markdown):
```markdown
## Why RSOLV?

RSOLV is the first AI security engineer that **proves vulnerabilities before fixing them** using executable test cases. No more false positives. No more wasted time reviewing AI-generated patches that don't address real issues.

### Real Vulnerabilities Only

Unlike traditional scanners, RSOLV validates every finding with an executable RED test before proposing a fix. If it can't demonstrate the vulnerability in a test, it doesn't report it.

### Test-First Security Methodology

1. **SCAN**: Detect vulnerabilities using 170+ AST-validated patterns
2. **VALIDATE**: Generate RED test proving the vulnerability exists
3. **MITIGATE**: Create fix that makes the test pass (GREEN)

### Key Features

- **170+ Security Patterns**: SQL injection, XSS, CSRF, RCE, path traversal, and more
- **OWASP Top 10 Coverage**: Comprehensive protection against common vulnerabilities
- **AST Validation**: Server-side validation prevents false positives (500/hour rate limit)
- **Multi-Language Support**: JavaScript, TypeScript, Python, Ruby, Go, Java
- **Educational PRs**: Every fix includes security context and prevention tips
- **External Tracker Integration**: Sync with Jira, Linear, GitHub Issues

### Pricing

- **Trial**: 10 free credits (no credit card required)
- **Pay-As-You-Go**: $29/month + usage
- **Pro Plan**: $599/month (500 credits included)

### Quick Start

1. Get API key: https://rsolv.dev
2. Add secret: `RSOLV_API_KEY`
3. Add workflow:

```yaml
name: RSOLV Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: RSOLV-dev/RSOLV-action@v1
        with:
          rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
          mode: scan
```

### Support

- **Documentation**: https://docs.rsolv.dev
- **Email**: support@rsolv.dev
- **Issues**: https://github.com/RSOLV-dev/RSOLV-action/issues

### License

Proprietary. See LICENSE file for terms.
```

### Step 6: Publish Release

1. Click "Publish release"
2. Action is **immediately published** to GitHub Marketplace (no review process)
3. Verify listing at: https://github.com/marketplace/actions/rsolv

**Note**: Unlike apps, GitHub Actions are published immediately without GitHub review.

## Post-Publication Monitoring

### Verification Steps
- [ ] Verify marketplace listing is live
- [ ] Test installation flow as new user
- [ ] Verify all links work (docs, support, repo)
- [ ] Check action appears in search results

### Common Issues (fix before publication):
- [ ] **Logo**: Create 500x500px PNG (shield icon, blue)
- [ ] **Screenshots**: Capture 3-5 high-quality images
- [ ] **Documentation**: Ensure docs.rsolv.dev is accessible (CRITICAL)
- [ ] **action.yml**: Validate syntax and metadata
- [ ] **Workflow templates**: Test end-to-end

### User Feedback Protocol

**For User Issues**:
1. Monitor GitHub Issues and Discussions
2. Respond within 24 hours (4 hours for critical)
3. Fix bugs within 48 hours
4. Update action and create new release

**Critical Path Items** (fix before submission):
- [ ] **docs.rsolv.dev DNS** - Must resolve before submission
- [ ] **Logo creation** - Need 500x500px PNG
- [ ] **Screenshots** - Capture 3-5 high-quality images

## Approval Checklist

When approval received:
- [ ] Verify marketplace listing is live
- [ ] Test installation flow as new user
- [ ] Verify all links work (docs, support, repo)
- [ ] Check SEO: Search "AI security GitHub Actions" - are we ranking?
- [ ] Activate monitoring for installation metrics
- [ ] Execute launch plan (see LAUNCH-PLAN.md)

## Rollback Plan

If issues found post-approval:
1. **Critical security issue**: Delist immediately, notify GitHub
2. **Major bug**: Add warning to README, ship fix within 48 hours
3. **Minor issue**: Document in known issues, fix in next release

## References

- **RFC-067**: `/home/dylan/dev/rsolv/RFCs/RFC-067-GITHUB-MARKETPLACE-PUBLISHING.md`
- **Week 1 Progress**: `docs/rfcs/RFC-067-WEEK-1-PROGRESS.md`
- **Marketplace Guidelines**: https://docs.github.com/en/actions/creating-actions/publishing-actions-in-github-marketplace

---

**Next**: After approval, execute launch plan (blog, social, HN, email)
