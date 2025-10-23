# RFC-067: GitHub Marketplace Publishing

**Status**: Draft
**Created**: 2025-10-12
**Updated**: 2025-10-21
**Timeline**: 2-3 weeks
**Dependencies**: RSOLV-action v3 stable

## Quick Start

**Repository**: https://github.com/RSOLV-dev/RSOLV-action
**Current Version**: v3.7.46+
**Installation**: Manual workflow file creation
**Target**: One-click marketplace install

## Summary

Publish RSOLV-action to GitHub Marketplace for discoverability, trust, and simplified installation. Currently requires manual setup; marketplace provides one-click install for millions of developers.

**Key Goals:**
- Increase discoverability among target developers (security, DevOps, backend)
- Reduce installation friction with marketplace-native experience
- Build trust through GitHub verification badge
- Enable go-to-market strategies for customer acquisition

## Problem

Current barriers to adoption:
- **No discovery mechanism** - Developers can't find us without direct links
- **Manual workflow file creation** - High friction installation process
- **Complex setup instructions** - Multi-step process increases drop-off
- **No GitHub verification badge** - Missing trust signal
- **Market silence** - No inbound customer acquisition channel

## Solution

### Required Updates to action.yml

**Current**: `RSOLV Issue Automation` (generic, forgettable)
**Proposed**: Marketing-focused naming and description

```yaml
name: 'RSOLV: Test-First AI Security Fixes'
author: 'RSOLV'
description: |
  Ship secure code faster. Test-first AI security that validates vulnerabilities with
  executable RED tests before fixing them. No guesswork—every fix is proven with tests
  that fail before and pass after. From detection to deployment in one workflow.

branding:
  icon: 'shield'
  color: 'blue'

inputs:
  rsolvApiKey:
    description: 'RSOLV API key for authentication (get yours at rsolv.dev/signup)'
    required: true

  mode:
    description: |
      Operation mode - choose based on your workflow:
      - 'scan': Full repository scan, creates GitHub issues (recommended starting point)
      - 'validate': Generate RED tests for labeled issues (use in separate job after scan)
      - 'mitigate': Apply fixes to validated issues (use in separate job after validate)
      - 'full': Run all three phases in single job (⚠️ can consume many credits at once)

      For production use, see workflow templates in RSOLV-action repo for multi-job patterns.
    required: false
    default: 'scan'

  github-token:
    description: |
      GitHub token for PR/issue operations. Automatically provided by GitHub Actions.
      Only override if you need custom permissions.
    required: false
    default: ${{ github.token }}

  # Additional commonly-used inputs
  max_issues:
    description: 'Maximum number of issues to process in a single run'
    required: false
    default: '1'

runs:
  using: 'docker'  # We use Docker, not Node
  image: 'Dockerfile'
```

**Key Changes:**
1. **Name**: "Test-First AI Security Fixes" (emphasizes unique validation approach)
2. **Description**: Test-first methodology front and center—validates with RED tests before fixing
3. **Mode parameter**: Updated descriptions match actual architecture, references workflow templates
4. **Default mode**: Changed from `'full'` to `'scan'` (prevents credit burn, safer onboarding)
5. **github-token**: Clarified it's auto-provided (from GitHub Actions automatic authentication)
6. **Runs**: Corrected to `docker` (matches our actual implementation, not `node20`)

**Rationale for github-token default:**
- GitHub Actions automatically provides `GITHUB_TOKEN` via `${{ github.token }}` context
- Users don't need to explicitly pass it unless they want different permissions
- Default works for 99% of use cases (create issues, open PRs, commit code)

### README Requirements

**License Decision:** Use **proprietary license** (not MIT) to protect competitive advantage.
- GitHub Marketplace allows commercial/proprietary actions
- MIT gives away code to competitors (Snyk, Sonar, etc.)
- Recommended: "Copyright © 2025 RSOLV. All rights reserved. See LICENSE for terms."

```markdown
# RSOLV: Test-First AI Security Fixes

[![GitHub Marketplace](badge)](link) [![Version](v3)](release)

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
- **Template**: [TEMPLATE-rsolv-simple-scan.yml](https://github.com/RSOLV-dev/rsolv-action/blob/main/.github/workflows/TEMPLATE-rsolv-simple-scan.yml)
- **Runtime**: ~1 minute
- **What it does**: Scan only, creates issues with `rsolv:detected` label

**Option B: Full Pipeline** (Advanced - better control)
Separate jobs for scan, validate, and fix phases with dependencies.
- **Template**: [TEMPLATE-rsolv-full-pipeline.yml](https://github.com/RSOLV-dev/rsolv-action/blob/main/.github/workflows/TEMPLATE-rsolv-full-pipeline.yml)
- **Runtime**: 5-10 minutes
- **What it does**: Full three-phase automation with job-level control

**Option C: Manual Setup**
Create `.github/workflows/rsolv-security.yml` from scratch:

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

**Why copy-paste is standard:** GitHub Actions marketplace works by providing YAML snippets
users copy into their workflow files. This is the native marketplace installation pattern.

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

## Support & Documentation

- 📧 Email: [support@rsolv.dev](mailto:support@rsolv.dev)
- 📖 Docs: [docs.rsolv.dev](https://docs.rsolv.dev)
- 💬 GitHub Issues: [Report bugs or request features](https://github.com/RSOLV-dev/rsolv-action/issues)
- 📚 Examples: [See RSOLV in action](https://github.com/RSOLV-dev/examples)

## License

Copyright © 2025 RSOLV. All rights reserved.

This software is proprietary. See [LICENSE](LICENSE) for terms.
```

---

**End of README template**. Content above (lines 109-211) goes in the actual README.md file for GitHub Marketplace. Content below is RFC implementation planning.

**Note on workflow template**: Copy-paste is the GitHub Actions marketplace standard.
The "Use this action" button shows users the YAML syntax to copy into their workflow file.
This is how all marketplace actions work—not a limitation, but the native pattern.

---

## Implementation Tasks

### Week 1: Preparation
- [ ] **Verify support infrastructure** exists and is functional:
  - [ ] Test `support@rsolv.dev` receives and can send email
  - [ ] Verify `docs.rsolv.dev` exists with minimum viable content (installation, troubleshooting)
  - [ ] Create/configure if missing (critical blocker for marketplace approval)
- [ ] Update action.yml with branding (icon: shield, color: blue)
- [ ] Create 500x500px logo.png for marketplace
- [ ] Rewrite README for marketplace format
- [ ] Add usage examples (basic, advanced, matrix)
- [ ] Test with marketplace validator
- [ ] Prepare screenshots of action in use
- [ ] **Add API rate limiting** to AST validation endpoint (500/hour per API key) using existing `Rsolv.RateLimiter` (Mnesia-based)
- [ ] Document rate limits in README and OpenAPI spec

### Week 2: Submission & Review
- [ ] Submit at github.com/marketplace/actions/new
- [ ] Select categories: Security, Code Quality, CI/CD
- [ ] Add description and keywords for SEO
- [ ] Respond to reviewer feedback (1-3 days)
- [ ] Fix any compliance issues
- [ ] Get approval notification

### Week 3: Launch & Optimize
- [ ] Announce on blog, social media, Dev.to
- [ ] Email growing contact list (building from zero)
- [ ] Monitor installation metrics
- [ ] Respond to user issues quickly
- [ ] Collect and showcase testimonials
- [ ] Optimize based on feedback

## Marketplace Metadata

```yaml
categories:
  - Security
  - Code quality
  - CI/CD

tags:
  - vulnerability-scanner
  - automated-fixes
  - ai-powered
  - devsecops

pricing_model: Free action, external API billing
verification:
  domain: rsolv.dev
  support: support@rsolv.dev
```

## Testing Checklist

### action.yml Validation
```bash
# Validate action metadata
npx action-validator action.yml

# Check for common issues
actionlint .github/workflows/*.yml
```

### Manual Installation Testing
**Test in multiple environments:**
- [ ] Fresh repo install (first-time user simulation)
- [ ] Secrets configuration (RSOLV_API_KEY setup)
- [ ] All operation modes:
  - [ ] `mode: scan` - Creates issues only (default, recommended start)
  - [ ] `mode: validate` - Generates tests for labeled issues
  - [ ] `mode: mitigate` - Applies fixes to validated issues
  - [ ] `mode: full` - Complete workflow in single job (credit warning works)
- [ ] Multi-job workflow templates:
  - [ ] TEMPLATE-rsolv-simple-scan.yml
  - [ ] TEMPLATE-rsolv-full-pipeline.yml (three separate jobs)
- [ ] Error handling (invalid API key, rate limits, etc.)
- [ ] Documentation clarity (can non-technical user follow?)

### End-to-End Testing with Real Repositories

**Test against diverse codebases to ensure reliability:**

1. **NodeGoat** (Deliberately vulnerable Node.js app)
   - Repo: https://github.com/RSOLV-dev/nodegoat-vulnerability-demo
   - Language: JavaScript (Express)
   - Expected: ~143 vulnerabilities detected (SQL injection, XSS, etc.)
   - Validates: JavaScript/TypeScript detection and fixing
   - **Cross-check**: Compare RSOLV findings against documented vulnerabilities (README, OWASP references)
   - **Success criteria**: Detect all documented vulnerabilities in categories RSOLV scans for (SQL injection, XSS, insecure crypto, etc.)

2. **RailsGoat** (Deliberately vulnerable Rails app)
   - Repo: https://github.com/OWASP/railsgoat
   - Language: Ruby (Rails)
   - Expected: Multiple OWASP Top 10 vulnerabilities
   - Validates: Ruby detection and framework-specific fixes
   - **Cross-check**: Compare RSOLV findings against documented vulnerabilities (tutorial documentation)
   - **Success criteria**: Detect all documented vulnerabilities in categories RSOLV scans for

3. **Real Open Source Project** (Production code quality)
   - Example: Medium-sized Node.js/Python/Ruby OSS project
   - Must NOT be deliberately vulnerable
   - Expected: 0-5 real issues (normal production code)
   - Validates: Low false positive rate, real-world applicability

**Testing Protocol for Each Repository:**
```bash
# 1. Fork repository to test account
# 2. Install RSOLV action via marketplace
# 3. Add RSOLV_API_KEY secret
# 4. Trigger workflow
# 5. Verify:
- Scan creates issues
- Validate generates passing tests
- Mitigate creates PR with fixes
- Tests pass in CI
- Documentation is clear
```

### Staging vs Dev vs CI Environments

**Development Environment:**
- Use `RSOLV_TESTING_MODE=true` for known vulnerable repos
- Local testing with `act` (RFC-059) - uses Claude Code Max, no API tokens
- Rapid iteration without consuming production credits

**Staging Environment:**
- Deployed RSOLV platform staging API
- Test with real GitHub Actions infrastructure
- Validate webhook handling, issue creation, PR generation
- Use test Stripe keys for billing validation

**CI Environment:**
- Automated testing in GitHub Actions
- Integration tests run on PR (see RFC-062)
- Uses staging API endpoint
- Validates action.yml changes don't break existing workflows

**Environment Variable Configuration:**
```yaml
# Development (local with act)
RSOLV_TESTING_MODE: 'true'
RSOLV_API_URL: 'http://localhost:4000'
CLAUDE_CODE_LOCAL: 'true'

# Staging
RSOLV_API_URL: 'https://rsolv-staging.com/api'
RSOLV_API_KEY: ${{ secrets.STAGING_API_KEY }}

# Production
RSOLV_API_URL: 'https://api.rsolv.dev'  # Default
RSOLV_API_KEY: ${{ secrets.RSOLV_API_KEY }}
```

### Testability Considerations

**Unit Tests:**
- Action input parsing and validation
- Mode selection logic
- Error handling for API failures

**Integration Tests:**
- Full workflow execution (scan → validate → mitigate)
- GitHub API interactions (issue creation, PR generation)
- Platform API communication

**Local Testing:**
- See RFC-059 for complete `act` setup
- Enables testing without GitHub Actions queue
- No API token consumption (uses Claude Code Max)

**Continuous Testing:**
- Pre-release testing in staging
- Canary releases to beta customers
- Rollback plan if marketplace release has issues

## Success Metrics

- **Installs**: 100+ in first month
- **Rating**: 4.5+ stars
- **Retention**: 60% active after 30 days
- **Conversion**: 10% to paid plans
- **Support**: <24 hour response

## Risks & Mitigation

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| **Market silence / No inbound** | **Critical** | **High** | **Multi-channel GTM strategy (see Launch Plan)** |
| Slow GitHub approval | Medium | Medium | Thorough preparation, clear documentation, responsive to feedback |
| Negative reviews | High | Medium | Excellent support (<24hr response), quick fixes, proactive communication |
| API instability | High | Low | Extensive testing (staging + canary), monitoring, rollback plan |
| Pricing confusion | Medium | Medium | Clear pricing in README, link to /pricing page, in-product guidance |
| Installation friction | Medium | Low | Step-by-step guide, video walkthrough, troubleshooting docs |
| Competitor response | Medium | High | Focus on unique value (validation + fixing), not just detection |
| Low conversion rate | High | Medium | Onboarding optimization, trial experience polish, upgrade CTAs |

### Critical Risk: Market Silence

**Problem:** Publishing to marketplace doesn't guarantee discovery. Most actions get <10 installs/month.

**Root Causes:**
- GitHub Marketplace has poor discovery (search is keyword-limited)
- "Security" category is crowded (Snyk, CodeQL, Semgrep, etc.)
- Developers stick with known brands
- No organic inbound without active promotion

**Mitigation Strategy - Multi-Channel Go-To-Market:**

1. **Warm Network Outreach** (Week 1-2, highest priority)
   - Personal outreach to connections who would actually use this product
   - Offer extended free credits for early feedback
   - "Kick the tires" beta program with personal support
   - Low-cost, high-value: immediate feedback + potential testimonials
   - Target: DevSecOps leads, security engineers, backend developers in network
   - Ask for honest feedback, not just usage

2. **Content Marketing** (Weeks 1-4)
   - Technical blog posts on dev.to, Medium (RSOLV in action)
   - Case studies: "How we reduced vulnerabilities by 80% with RSOLV"
   - Comparison content: "RSOLV vs traditional SAST tools"
   - SEO-optimized landing pages

3. **Community Engagement** (Ongoing)
   - Mastodon/Fediverse: `@rsolv@infosec.exchange` - technical threads, vulnerability insights
   - Bluesky: Security community building
   - Reddit: r/netsec, r/devops (careful, no spam)
   - GitHub Discussions: Help users, showcase successes
   - Hacker News: Launch announcement, Show HN posts

4. **Direct Outreach** (Weeks 2-6)
   - Build and grow email list (**Note:** Currently no waiting list; will grow via marketplace signups and warm network referrals)
   - LinkedIn: Target DevSecOps leads at mid-size companies
   - Developer newsletters: Sponsor JavaScript Weekly, Ruby Weekly, etc.

5. **Partnership & Integration** (Months 2-3)
   - GitHub Stars program (if eligible)
   - Integration with popular repos (offer free scans to high-profile OSS)
   - Conference speaking (All Day DevOps, DevSecCon, etc.)

6. **Paid Acquisition** (If budget allows)
   - Google Ads: "automated vulnerability fixing" keywords
   - Dev.to sponsored posts
   - GitHub Actions blog sponsored mentions

**Success Indicators:**
- 15-30 installs in first month (conservative cold start baseline)
- 3-6 trial signups from marketplace (~20% conversion)
- 1-2 paying customers from marketplace in first 3 months

## Analytics Implementation

**Events to Track** (anonymized, no PII):

```javascript
// Optional, anonymized telemetry (opt-in via environment variable)
class Analytics {
  track(event, metadata = {}) {
    if (process.env.RSOLV_TELEMETRY !== 'false' && hasConsent()) {
      telemetry.send({
        event,
        source: 'marketplace',
        version: VERSION,
        timestamp: Date.now(),
        ...metadata  // Event-specific context
      })
    }
  }
}

// Action Lifecycle Events
analytics.track('action_started', {
  mode: 'full',
  trigger: 'push'  // push, pull_request, schedule, workflow_dispatch
})

analytics.track('action_completed', {
  mode: 'full',
  duration_ms: 45000,
  success: true
})

analytics.track('action_failed', {
  mode: 'scan',
  error_type: 'api_auth_failed',
  duration_ms: 5000
})

// Phase-Specific Events
analytics.track('scan_completed', {
  vulnerabilities_found: 12,
  languages: ['javascript', 'python'],
  false_positives_filtered: 3
})

analytics.track('validate_completed', {
  tests_generated: 5,
  tests_passed: 0,  // RED tests should fail
  framework: 'jest'
})

analytics.track('mitigate_completed', {
  fixes_applied: 5,
  pr_created: true,
  tests_now_pass: true
})

// Usage & Conversion Events
analytics.track('marketplace_install', {
  referrer: 'github_search'  // or 'blog', 'social', 'direct'
})

analytics.track('first_successful_scan', {
  days_since_install: 0,
  vulnerabilities_found: 8
})

analytics.track('credits_depleted', {
  credits_used: 10,
  days_since_signup: 7,
  has_billing_info: false  // Important for conversion tracking
})

analytics.track('upgrade_initiated', {
  from_plan: 'trial',  // trial is a subscription_plan value (initial state)
  to_plan: 'pro',
  source: 'dashboard',  // or 'marketplace_readme', 'credits_warning'
  credits_remaining: 0  // Useful for understanding upgrade triggers
})
```

**Metadata Guidelines:**
- **No PII**: No emails, usernames, repo names, or code snippets
- **Aggregate only**: Count vulnerabilities, not their details
- **Opt-out available**: `RSOLV_TELEMETRY=false` disables all tracking
- **Transparency**: Document what we track in privacy policy

**Privacy-First Approach:**
```yaml
# In action.yml or workflow
inputs:
  telemetry:
    description: 'Enable anonymized usage analytics (default: true)'
    required: false
    default: 'true'
```

**Analytics Goals:**
1. Understand adoption funnel (install → first scan → upgrade)
2. Identify drop-off points (where users abandon)
3. Measure mode usage (is anyone using 'validate' alone?)
4. Track error rates (API failures, timeout issues)
5. Inform product roadmap (which languages, frameworks are popular)

## Launch Plan

### Pre-Launch (Week before marketplace approval)

**Content Preparation:**
- [ ] Blog post: "Introducing RSOLV: AI Security Engineer for GitHub Actions"
- [ ] Email template for growing contact list (building from marketplace signups)
- [ ] Social media content calendar (Mastodon, Bluesky)
- [ ] Video walkthrough: 3-minute "Install to first scan" screencast
- [ ] FAQ documentation: Common questions, troubleshooting
- [ ] Press kit: Logos, screenshots, value props, founder bio

**Technical Preparation:**
- [ ] Staging environment tested with marketplace workflow
- [ ] Monitoring and alerting configured
- [ ] Support email inbox ready (support@rsolv.dev)
- [ ] Rollback plan documented
- [ ] Rate limits configured to handle surge

### Launch Day (Marketplace approval received)

**Immediate Actions (Hour 0-4):**
1. **Publish announcement blog post** on rsolv.dev
2. **Email warm network contacts** with installation guide and exclusive early access offer (**Note:** No waiting list yet; starting with warm network)
3. **Social media blitz:**
   - **Mastodon** (`@rsolv@infosec.exchange`): Technical thread on how RSOLV works, vulnerability validation approach
   - **Bluesky**: Launch announcement with value prop, link to marketplace
   - **LinkedIn**: Professional announcement targeting DevSecOps leads
   - ~~Twitter~~ (dropped - low ROI, toxic environment)
4. **Hacker News**: "Show HN: RSOLV - AI that validates vulnerabilities before fixing them"
5. **Dev.to article**: "How we built an AI security engineer that generates executable tests"

**Community Engagement (Hour 4-24):**
- [ ] Post in r/netsec, r/devops, r/github (carefully, provide value)
- [ ] Share in relevant Discord servers (DevSecOps, GitHub Actions)
- [ ] GitHub Discussions: Create "Ask us anything" thread
- [ ] Respond to all comments, questions, feedback within 1 hour

**Media Outreach (Day 1-3):**
- [ ] Email dev-focused publications: The New Stack, InfoQ, DevOps.com
- [ ] Podcast pitches: Software Engineering Daily, The Changelog
- [ ] Newsletter features: JavaScript Weekly, Ruby Weekly, Python Weekly

### Post-Launch (Week 1-4)

**Daily Monitoring:**
- [ ] Track installs, trial signups, conversions
- [ ] Monitor social media mentions, GitHub issues, support emails
- [ ] Respond to all support requests within 24 hours (goal: <4 hours)
- [ ] Fix critical bugs within 48 hours

**Weekly Iteration:**
- [ ] Publish weekly usage stats (if impressive): "Week 1: 150 installs, 50 vulnerabilities fixed"
- [ ] Share customer success stories (with permission)
- [ ] Write follow-up content: case studies, technical deep-dives
- [ ] Optimize based on feedback (README clarity, installation friction)

**Engagement Cadence:**
- **Mastodon**: Daily technical insights, vulnerability research, user wins
- **Bluesky**: 3x/week updates, community building
- **LinkedIn**: Weekly professional updates, company milestones
- **Blog**: Bi-weekly technical articles, case studies
- **Email**: Monthly newsletter to users (product updates, tips, success stories)

### Success Metrics (30/60/90 Days)

**30 Days (Conservative Targets):**
- 15-30 marketplace installs
- 3-6 trial signups
- 1-2 paying customers
- 4.5+ star rating (if we get reviews)

**60 Days (Growth Targets):**
- 40-75 marketplace installs (cumulative)
- 8-15 trial signups (cumulative)
- 3-5 paying customers (cumulative)
- Case study published from early adopter

**90 Days (Scale Targets):**
- 80-150 marketplace installs (cumulative)
- 16-30 trial signups (cumulative)
- 6-10 paying customers (cumulative)
- Featured in at least one major publication

**Pivot Indicators (When to adjust strategy):**
- <10 installs in first 30 days → Reassess GTM strategy, increase marketing
- <15% trial signup rate → Improve onboarding, reduce friction
- High churn (>50% in 7 days) → Polish trial experience, add value
- Negative reviews → Emergency support/fix cycle, over-communicate

## Support Infrastructure Validation

**Before marketplace submission, verify these exist and work:**

### Email Support
- [ ] `support@rsolv.dev` configured and monitored
- [ ] Auto-responder set up (acknowledge within 5 minutes)
- [ ] Support team trained on common issues
- [ ] SLA defined: <24 hour response, <48 hour resolution for critical bugs

### Documentation Site
- [ ] `docs.rsolv.dev` accessible and complete
- [ ] Installation guide (step-by-step with screenshots)
- [ ] Troubleshooting section (common errors, solutions)
- [ ] API reference (if exposing advanced features)
- [ ] Examples repository (working code samples)
- [ ] Video tutorials (optional but helpful)

### Support Channels Status
**Current state** (as of 2025-10-23):
- ⚠️ `support@rsolv.dev` - Email address referenced in codebase, **needs verification that it's configured and monitored**
- ⚠️ `docs.rsolv.dev` - Documentation URL referenced in codebase, **needs verification that it exists and has content**
- **Critical**: Both must be fully functional before marketplace launch. Marketplace reviewers may check these links.
- **Week 1 task**: Verify existence, create/configure if missing, populate with minimum viable documentation

## Next Steps

### Week 1: Preparation & Assets
1. [ ] **Update action.yml** with marketplace-ready metadata
   - Marketing-focused name and description
   - Complete input documentation (all 5 modes)
   - Branding (shield icon, blue color)
2. [ ] **Create marketplace assets**
   - 500x500px logo (high-quality PNG)
   - Screenshots of action in use (scan, validate, mitigate)
   - Video demo (optional but recommended)
3. [ ] **Rewrite README** for marketplace
   - Benefit-driven copy
   - Clear quick start guide
   - Pricing transparency
   - Support links
4. [ ] **Validate support infrastructure**
   - Test support@rsolv.dev inbox
   - Review docs.rsolv.dev content
   - Prepare FAQ and troubleshooting guides
5. [ ] **Run comprehensive testing**
   - NodeGoat, RailsGoat, real OSS project
   - All 5 operation modes
   - Dev, staging, CI environments

### Week 2: Submission & Review
1. [ ] **Submit to GitHub Marketplace**
   - github.com/marketplace/actions/new
   - Select categories: Security, Code Quality, CI/CD
   - Add SEO keywords: vulnerability, security, automated fixing, AI
2. [ ] **Respond to reviewer feedback**
   - Typically 1-3 day turnaround
   - Address compliance issues promptly
   - Update metadata as needed
3. [ ] **Prepare launch materials**
   - Blog post draft
   - Email template for warm network outreach (no waiting list yet)
   - Social media posts (Mastodon, Bluesky, LinkedIn)
   - Hacker News post draft

### Week 3: Launch & Monitor
1. [ ] **Get marketplace approval**
   - Celebrate! 🎉
   - Final pre-launch checks
2. [ ] **Execute launch plan**
   - Publish blog post
   - Email warm network contacts (no waiting list yet)
   - Social media blitz (Mastodon, Bluesky, LinkedIn)
   - Hacker News Show HN
3. [ ] **Monitor and respond**
   - Track installs, signups, conversions
   - Respond to all feedback within 4 hours
   - Fix critical bugs within 48 hours
4. [ ] **Iterate based on feedback**
   - Update README for clarity
   - Add examples for common use cases
   - Optimize onboarding flow

### Post-Launch: Continuous Improvement
- Weekly: Publish usage stats, share success stories
- Bi-weekly: Technical blog posts, case studies
- Monthly: Product updates, new features, metrics review
- Quarterly: Major feature releases, customer survey