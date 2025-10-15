# RFC-067: GitHub Marketplace Publishing

**Status**: Draft
**Created**: 2025-10-12
**Timeline**: 2-3 weeks
**Dependencies**: RSOLV-action v3 stable

## Quick Start

**Repository**: https://github.com/RSOLV-dev/RSOLV-action
**Current Version**: v3.7.46+
**Installation**: Manual workflow file creation
**Target**: One-click marketplace install

## Summary

Publish RSOLV-action to GitHub Marketplace for discoverability, trust, and simplified installation. Currently requires manual setup; marketplace provides one-click install for millions of developers.

## Problem

Current barriers to adoption:
- No discovery mechanism
- Manual workflow file creation
- Complex setup instructions
- No GitHub verification badge

## Solution

### Required Updates to action.yml

```yaml
name: 'RSOLV Security Scanner'
author: 'RSOLV'
description: 'AI-powered vulnerability detection and automated fixing'
branding:
  icon: 'shield'
  color: 'blue'

inputs:
  api-key:
    description: 'RSOLV API key'
    required: true
  mode:
    description: 'scan, validate, or mitigate'
    default: 'scan'
  github-token:
    description: 'GitHub token for PR/issue ops'
    default: ${{ github.token }}

runs:
  using: 'node20'
  main: 'dist/index.js'
```

### README Requirements

```markdown
# RSOLV Security Scanner

[![Marketplace](badge)](link) [![License](MIT)](LICENSE)

## Features
🔍 Automatic vulnerability detection
✅ False positive validation with framework-native test integration
🔧 Automated fix generation
📊 Detailed reporting
🧪 Tests integrated directly into your existing test directories (spec/, __tests__/, tests/)

## Quick Start
1. Click "Use this action" above
2. Get API key at [rsolv.dev](https://rsolv.dev)
3. Add secret: RSOLV_API_KEY
4. Create workflow:

```yaml
uses: RSOLV-dev/rsolv-action@v3
with:
  api-key: ${{ secrets.RSOLV_API_KEY }}
  mode: scan
```

## Pricing
- 10 free fixes
- $15/fix PAYG
- $499/month Teams

## Support
📧 support@rsolv.dev
📖 [Documentation](https://docs.rsolv.dev)
```

## Implementation Tasks

### Week 1: Preparation
- [ ] Update action.yml with branding (icon: shield, color: blue)
- [ ] Create 500x500px logo.png for marketplace
- [ ] Rewrite README for marketplace format
- [ ] Add usage examples (basic, advanced, matrix)
- [ ] Test with marketplace validator
- [ ] Prepare screenshots of action in use

### Week 2: Submission & Review
- [ ] Submit at github.com/marketplace/actions/new
- [ ] Select categories: Security, Code Quality, CI/CD
- [ ] Add description and keywords for SEO
- [ ] Respond to reviewer feedback (1-3 days)
- [ ] Fix any compliance issues
- [ ] Get approval notification

### Week 3: Launch & Optimize
- [ ] Announce on blog, social media, Dev.to
- [ ] Email waiting list (~100 contacts)
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

```bash
# Validate action.yml
npx action-validator action.yml

# Test installation flow
- Fresh repo install
- Secrets configuration
- All three modes (scan/validate/mitigate)
- Error handling
- Documentation clarity
```

## Success Metrics

- **Installs**: 100+ in first month
- **Rating**: 4.5+ stars
- **Retention**: 60% active after 30 days
- **Conversion**: 10% to paid plans
- **Support**: <24 hour response

## Risks & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| Slow approval | Medium | Thorough preparation |
| Negative reviews | High | Excellent support, quick fixes |
| API instability | High | Extensive testing, monitoring |

## Analytics Implementation

```javascript
// Optional, anonymized telemetry
class Analytics {
  track(event, props) {
    if (hasConsent()) {
      telemetry.send({
        event,
        source: 'marketplace',
        version: VERSION,
        // No PII
      })
    }
  }
}
```

## Launch Plan

1. **Pre-Launch**: Blog post draft, email template, social media
2. **Launch Day**: Submit to HN, Dev.to article, Twitter thread
3. **Post-Launch**: Daily monitoring, rapid response, gather feedback

## Next Steps

1. Update action.yml with branding
2. Create marketplace assets (logo, screenshots)
3. Rewrite README for marketplace
4. Submit for review