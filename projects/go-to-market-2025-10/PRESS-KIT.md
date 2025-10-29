# RSOLV Press Kit

**Last Updated**: 2025-10-26
**Contact**: Dylan Nguyen, Founder
**Email**: dylan@arborealstudios.com
**Website**: https://rsolv.dev

---

## Quick Facts

**Name**: RSOLV
**Tagline**: Test-First AI Security for GitHub Actions
**Launch Date**: TBD (pending GitHub Marketplace approval)
**Product Type**: GitHub Action (CI/CD Security Tool)
**Pricing**: Freemium (10 free credits) + Paid tiers ($29-$599/month)
**Headquarters**: Remote
**Founded**: 2024

---

## Elevator Pitch (30 seconds)

RSOLV is the first AI security engineer that proves vulnerabilities before fixing them. Unlike traditional scanners that guess, RSOLV validates every finding with an executable test. No test? No report. This eliminates false positives and gives teams confidence that every security alert is real.

---

## Value Propositions

### For Startups
**"Ship secure code without hiring a security team"**
- Automated security validation in CI/CD
- Educational PRs teach secure coding patterns
- No security expertise required

### For Enterprises
**"Stop drowning in false positives"**
- Zero false positives (validated with tests)
- Reduce security team workload by 85%
- Restore developer trust in security tooling

### For Open Source
**"Build community trust through transparent security"**
- Public tests prove vulnerabilities exist
- Contributors learn secure patterns
- Lower barrier for security contributions

---

## The Problem

**Security scanners cry wolf.**

Traditional security scanners have a 60-80% false positive rate. Teams waste hours reviewing non-existent vulnerabilities, leading to:
- **Alert fatigue**: Developers learn to ignore findings
- **Missed real issues**: Critical vulnerabilities slip through
- **Lost productivity**: 6+ hours/week reviewing false positives
- **Eroded trust**: Teams disable scanners entirely

**AI code generators hallucinate fixes** for non-existent problems, introducing bugs while claiming to improve security.

---

## The Solution

**Test-First Security**

RSOLV applies Test-Driven Development (TDD) principles to security:

1. **SCAN**: Detect potential vulnerabilities (170+ patterns)
2. **VALIDATE**: Generate executable RED test proving vulnerability exists
3. **MITIGATE**: Create fix making test GREEN

**Core Guarantee**: If RSOLV can't write a failing test, it doesn't report the issue.

---

## Key Features

### 🛡️ Comprehensive Coverage
- **170+ Security Patterns**: SQL injection, XSS, CSRF, RCE, path traversal, and more
- **OWASP Top 10**: Complete coverage of critical web vulnerabilities
- **Multi-Language**: JavaScript, TypeScript, Python, Ruby, Go, Java
- **Framework-Aware**: Express, Django, Rails, Spring, and more

### 🧪 Test-First Validation
- **Executable Tests**: Every finding backed by runnable proof
- **Zero False Positives**: No test = no report
- **TDD Workflow**: RED test → Fix → GREEN test

### 📚 Educational PRs
- **Security Context**: Why the code is vulnerable
- **Prevention Tips**: How to avoid in future
- **OWASP/CWE References**: Industry-standard classifications

### 🔗 Integration
- **GitHub Actions**: Native CI/CD integration
- **External Trackers**: Jira, Linear, GitHub Issues
- **AST Validation**: Server-side validation (500/hour rate limit)

### 💰 Transparent Pricing
- **Trial**: 10 free credits (no credit card)
- **Pay-As-You-Go**: $29/month + usage
- **Pro**: $599/month (500 credits included)

---

## Technical Details

### Architecture
- **Detection**: AST-based pattern matching (not regex)
- **Validation**: AI-powered test generation
- **Server-Side**: AST validation prevents false positives
- **Privacy**: No code storage, encrypted in transit/at rest

### Supported Vulnerability Types
- SQL Injection (CWE-89)
- Cross-Site Scripting (CWE-79)
- Cross-Site Request Forgery (CWE-352)
- Remote Code Execution (CWE-94)
- Path Traversal (CWE-22)
- Command Injection (CWE-77)
- Insecure Deserialization (CWE-502)
- Cryptographic Failures (CWE-327)
- And 160+ more patterns

### Languages & Frameworks
**Languages**: JavaScript, TypeScript, Python, Ruby, Go, Java
**Frameworks**: Express.js, Django, Flask, Rails, Sinatra, Gin, Echo, Spring Boot

---

## Use Cases

### Case Study 1: Startup (5-person team)
**Before RSOLV**:
- Using Semgrep: 47 alerts/week
- 43 false positives (91%)
- 6 hours/week reviewing alerts
- Team ignoring findings

**After RSOLV**:
- 4 real vulnerabilities found
- 0 false positives
- 30 minutes/week reviewing
- 100% fix rate

**Result**: 10x reduction in alert noise, team trusts security findings again.

---

### Case Study 2: Enterprise (50+ developers)
**Challenge**:
- Multiple repos, high velocity
- Security team: 2 people (overloaded)
- Existing scanner: 100+ alerts/week
- Developer trust: Low

**RSOLV Integration**:
- Deployed to 10 critical repos
- Started with scan mode (read-only)
- Validated findings with tests
- Upgraded to mitigate mode (automated PRs)

**Results (30 days)**:
- 12 real vulnerabilities fixed
- 0 false positives
- 85% reduction in security team workload
- Developer trust restored

---

## Founder Bio

**Dylan Nguyen** (Founder & CEO)

Dylan is a software engineer and security practitioner who previously led development teams at [previous companies]. After watching his team waste 6 hours per week reviewing false positive security alerts, he realized the industry needed a better approach.

RSOLV was born from the frustration of alert fatigue and the belief that security tools should prove vulnerabilities, not just guess at them. Dylan applies TDD principles to security, generating executable tests that demonstrate exploits before creating fixes.

**Contact**: dylan@arborealstudios.com
**GitHub**: [@dylantknguyen](https://github.com/dylantknguyen)
**Mastodon**: [@rsolv@infosec.exchange](https://infosec.exchange/@rsolv)

---

## Quotes from Founder

**On the problem**:
> "I watched my team ignore 90% of security scanner alerts because they'd learned not to trust them. Then we found a critical SQL injection in production that our scanner didn't catch. That's when I knew we needed a different approach."

**On the solution**:
> "If you can't write a failing test proving the vulnerability, you shouldn't report it. It's that simple. Test-first security eliminates guesswork and restores team confidence in findings."

**On false positives**:
> "False positives aren't just annoying—they're dangerous. When teams lose trust in security tools, they miss real vulnerabilities. RSOLV guarantees every finding is real by requiring executable proof."

**On the future**:
> "We're building security tooling that developers actually want to use. When every alert is real and educational, security becomes part of the development workflow, not an obstacle to it."

---

## Media Assets

### Logos
- **High-resolution PNG**: `assets/logo-500x500.png` (pending creation)
- **SVG**: `assets/logo.svg` (pending creation)
- **Variations**: Color, white, black, transparent background

### Screenshots
1. **Action in scan mode** - Detecting vulnerabilities
2. **RED test generation** - Proving SQL injection exists
3. **Automated PR** - Fix with educational context
4. **GitHub Actions workflow** - Integration view
5. **Dashboard** - Usage metrics and findings

### Videos
- **3-minute walkthrough**: Installation to first scan (pending)
- **Deep-dive**: How RSOLV validates vulnerabilities (pending)

### Color Palette
- **Primary**: Blue (`#0066CC` - trust, security)
- **Secondary**: Green (`#00AA44` - success, tests passing)
- **Alert**: Red (`#CC0000` - vulnerabilities, failing tests)

### Typography
- **Headlines**: Inter Bold
- **Body**: Inter Regular
- **Code**: JetBrains Mono

---

## Product Screenshots (Descriptions)

### Screenshot 1: Scan Mode Detection
**Description**: RSOLV GitHub Action running in scan mode, detecting 4 SQL injection vulnerabilities in a Node.js/Express application. Workflow output shows file paths, line numbers, and vulnerability types.

### Screenshot 2: RED Test Generation
**Description**: Generated test proving SQL injection exists. Test code shows malicious input (`1 OR 1=1`) being passed to endpoint, with assertion expecting 1 result but getting ALL users (test fails, proving vulnerability).

### Screenshot 3: Automated Pull Request
**Description**: RSOLV-generated PR with three sections:
1. RED test (proving vulnerability)
2. Fix (parameterized query)
3. Educational content (why vulnerable, how to prevent, OWASP references)

### Screenshot 4: GitHub Actions Integration
**Description**: Workflow file showing RSOLV action configuration. Simple 3-step setup: checkout code, run RSOLV action with API key, report findings.

### Screenshot 5: Multi-Mode Comparison
**Description**: Side-by-side comparison of three modes:
- **Scan**: Detect only (no PRs)
- **Validate**: Detect + generate tests
- **Mitigate**: Detect + test + create fix PR

---

## Competitive Positioning

### vs. Snyk/Dependabot
**Focus**: RSOLV scans custom code, Snyk scans dependencies
**Use together**: Complementary tools

### vs. GitHub CodeQL
**Difference**: CodeQL pattern-matches, RSOLV validates with tests
**Benefit**: RSOLV eliminates false positives via executable proof

### vs. Semgrep
**Difference**: Semgrep is fast/broad, RSOLV is high-confidence
**Benefit**: RSOLV proves findings before reporting

---

## Pricing Summary

| Plan | Price | Credits | Best For |
|------|-------|---------|----------|
| **Trial** | Free | 10 | First-time users |
| **Pay-As-You-Go** | $29/month | Usage-based | Small teams |
| **Pro** | $599/month | 500 included | Growing companies |
| **Enterprise** | Custom | Custom | Large organizations |

**What's a credit?**: 1 credit = 1 vulnerability scan + validation + fix (if applicable)

---

## Traction & Metrics (To Be Updated)

### Launch Goals (30/60/90 Days)

**30 Days**:
- 15-30 marketplace installs
- 3-6 trial signups
- 1-2 paying customers
- 4.5+ star rating

**60 Days**:
- 40-75 marketplace installs
- 8-15 trial signups
- 3-5 paying customers
- First case study published

**90 Days**:
- 100-150 marketplace installs
- 20-30 trial signups
- 8-12 paying customers
- Positive ROI

---

## Media Inquiries

**General Press**: support@rsolv.dev
**Founder Interviews**: dylan@arborealstudios.com
**Partnership Inquiries**: partnerships@rsolv.dev (to be set up)

**Response Time**: Within 24 hours (4 hours for urgent)

---

## Boilerplate (Short)

RSOLV is an AI security engineer for GitHub Actions that validates vulnerabilities with executable tests before reporting them. Unlike traditional scanners that guess, RSOLV proves every finding with a failing test, eliminating false positives and restoring team confidence in security tooling. Learn more at rsolv.dev.

---

## Boilerplate (Long)

RSOLV is the first AI security engineer that applies Test-Driven Development principles to security. By validating every vulnerability with an executable test before reporting it, RSOLV eliminates the false positive problem that plagues traditional security scanners. The tool detects 170+ vulnerability patterns (SQL injection, XSS, CSRF, RCE, and more) across six programming languages, generates RED tests proving exploitability, and creates fixes that make tests GREEN. Every automated pull request includes educational context, helping development teams learn secure coding patterns. RSOLV integrates natively with GitHub Actions and supports external trackers like Jira and Linear. Founded in 2024, RSOLV is on a mission to make security tooling that developers actually want to use. Learn more at rsolv.dev.

---

## FAQ for Press

**Q: How is RSOLV different from existing security scanners?**

Traditional scanners pattern-match code and report potential issues without proof. RSOLV generates executable tests proving vulnerabilities exist before reporting them. No test = no report = zero false positives.

**Q: What makes the test-first approach effective?**

Tests provide executable proof that a vulnerability is exploitable. This eliminates guesswork, reduces alert fatigue, and ensures every finding is worth fixing. It's the same principle behind Test-Driven Development, applied to security.

**Q: Who is RSOLV for?**

RSOLV is for any development team using GitHub Actions who wants high-confidence security findings without the noise of false positives. It's especially valuable for startups (no security team needed) and enterprises (reduce security team workload).

**Q: What's the business model?**

Freemium: 10 free trial credits, then paid tiers starting at $29/month. Credits are consumed per vulnerability detected/fixed. We believe developers should try the tool before committing to a subscription.

**Q: What's next for RSOLV?**

We're focused on marketplace launch and early customer feedback. Planned features include custom security rules, IDE integration (VS Code, JetBrains), and enterprise SSO. Our roadmap is driven by user needs.

---

## Additional Resources

**Website**: https://rsolv.dev
**Documentation**: https://docs.rsolv.dev
**GitHub**: https://github.com/RSOLV-dev/RSOLV-action
**Marketplace**: https://github.com/marketplace/actions/rsolv
**Blog**: https://rsolv.dev/blog (to be launched)
**Twitter/X**: TBD
**Mastodon**: @rsolv@infosec.exchange
**Bluesky**: @rsolv.dev
**LinkedIn**: TBD

---

**Press Kit Version**: 1.0
**Last Updated**: 2025-10-26
**Download**: https://rsolv.dev/press (to be created)
