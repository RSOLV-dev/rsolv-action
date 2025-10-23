# RSOLV Customer Demo Video Recording Checklist

## ✅ Pre-Recording Setup
- [x] Production deployment complete with cache fix
- [x] Health check passed
- [x] Demo repository ready (RSOLV-dev/nodegoat-vulnerability-demo)
- [x] Issues available for demonstration (#552, #553, #554, #550, #551)
- [ ] Admin access to production dashboard
- [ ] Valid production API key for demo customer
- [ ] Screen recording software ready
- [ ] Quiet environment for recording

## 📹 Recording Script (10-15 minutes total)

### Phase 0: PROVISION (2-3 minutes)
- [ ] Navigate to https://rsolv.dev/admin/login
- [ ] Show admin dashboard overview
- [ ] Create "Demo Customer" account
  - Email: demo@example.com
  - Monthly Limit: 1000 fixes
  - Active: Yes
- [ ] Generate API key
- [ ] Show key management features
- [ ] Highlight instant revocation capability

### Phase 1: SCAN (2-3 minutes)
- [ ] Navigate to GitHub repo: RSOLV-dev/nodegoat-vulnerability-demo
- [ ] Show existing issues with rsolv:detected label
- [ ] Explain automatic scanning on push/PR
- [ ] Highlight detection time: < 1 minute
- [ ] Show vulnerability categorization

### Phase 2: VALIDATE - Optional (1-2 minutes)
- [ ] Select issue #553 (XSS vulnerability)
- [ ] Add `rsolv:validate` label
- [ ] Explain AST validation process
- [ ] Show 99% accuracy improvement
- [ ] Demonstrate false positive reduction

### Phase 3: MITIGATE (3-8 minutes)
- [ ] Select issue #552 (Hardcoded secrets)
- [ ] Add `rsolv:automate` label
- [ ] Watch GitHub Action trigger
- [ ] Show credential vending process
- [ ] Wait for PR creation
- [ ] Review generated PR:
  - Fix implementation
  - Test coverage
  - Educational content
  - Security best practices
- [ ] Highlight production-ready quality

### Phase 4: MONITOR (2 minutes)
- [ ] Return to admin dashboard
- [ ] Navigate to Demo Customer details
- [ ] Show usage statistics
- [ ] Demonstrate API key management
- [ ] Review audit logs
- [ ] Show monthly usage tracking

## 🎯 Key Messages to Emphasize
- **Enterprise Control**: Full admin provisioning and management
- **Speed**: < 1 minute detection, < 1 minute fixes
- **Accuracy**: 99% with AST validation
- **Quality**: Production-ready fixes with tests
- **ROI**: 296,000% return on investment
- **Security**: No code storage, client-side encryption
- **Compliance**: Complete audit trail

## 📊 Metrics to Highlight
- Detection time: 56 seconds average
- Fix generation: 48 seconds average
- Validation accuracy: 99%
- Cost savings: $450 per vulnerability fixed
- Time savings: 4 hours per vulnerability

## 🚀 Post-Recording
- [ ] Review video for quality
- [ ] Add intro/outro if needed
- [ ] Upload to secure location
- [ ] Share with sales team
- [ ] Create shorter clips for specific features

## 📝 Notes
- Keep energy high and pace steady
- Focus on value propositions
- Use customer-centric language
- Avoid technical jargon where possible
- Emphasize ease of use and control

## URLs for Demo
- Production Admin: https://rsolv.dev/admin
- Demo Repository: https://github.com/RSOLV-dev/nodegoat-vulnerability-demo
- Production API: https://api.rsolv.dev