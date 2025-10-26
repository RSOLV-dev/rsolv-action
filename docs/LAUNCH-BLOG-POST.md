# Introducing RSOLV: AI Security Engineer for GitHub Actions

**Date**: TBD (Marketplace approval day)
**Author**: Dylan (RSOLV Founder)
**Target**: rsolv.dev/blog, Dev.to, Medium
**SEO Keywords**: AI security, GitHub Actions, vulnerability detection, automated security fixes

---

## The Problem: False Positive Fatigue

Security scanners cry wolf. A lot.

You've seen it: Your CI pipeline flags 47 "critical vulnerabilities." You spend 3 hours reviewing them. 43 are false positives. The 4 real issues? Already on your backlog, deprioritized because you're drowning in noise.

**Traditional scanners guess**. They pattern-match code and hope they're right. They can't prove a vulnerability exists—they just suspect it might.

**AI code generators hallucinate**. They'll happily "fix" non-existent issues, introducing bugs while claiming to improve security.

**You deserve better.**

## The Solution: Test-First AI Security

RSOLV is the first AI security engineer that **proves vulnerabilities before fixing them**.

No guesswork. No false positives. No wasted time.

### How It Works: RED → GREEN Security

RSOLV follows Test-Driven Development principles, applied to security:

**1. SCAN** - Detect potential vulnerabilities using 170+ AST-validated patterns
- SQL injection, XSS, CSRF, RCE, path traversal, crypto failures
- OWASP Top 10 coverage
- Multi-language support (JS, TS, Python, Ruby, Go, Java)

**2. VALIDATE** - Generate executable RED test proving the vulnerability exists
- If RSOLV can't write a failing test, it doesn't report the issue
- Tests demonstrate real exploit scenarios
- Server-side AST validation ensures quality

**3. MITIGATE** - Create fix that makes the test GREEN
- Automated pull request with patch
- Educational security context included
- Prevention tips for your team

### Real Vulnerabilities Only

Here's the guarantee: **If RSOLV reports a vulnerability, it can prove it with an executable test.**

No test? No report. Simple.

This approach eliminates false positives and gives you confidence that every finding is worth fixing.

## Features

### 🛡️ Comprehensive Security Coverage
- **170+ Detection Patterns**: From OWASP Top 10 to SANS Top 25
- **AST Validation**: Server-side validation (500/hour rate limit per API key)
- **Multi-Language**: JavaScript, TypeScript, Python, Ruby, Go, Java
- **Framework-Aware**: Express, Django, Rails, Spring, and more

### 🧪 Test-First Methodology
- **Executable Tests**: RED tests prove vulnerabilities exist
- **TDD Workflow**: Validate → Fix → Verify (GREEN)
- **Educational Output**: Every PR includes security context

### 🔄 Flexible Workflow Modes
- **Scan**: Detect and report (read-only, no PR creation)
- **Validate**: Scan + generate RED tests
- **Mitigate**: Scan + validate + create fix PRs (full automation)

### 🔗 External Tracker Integration
- **Jira**: Auto-create security tickets
- **Linear**: Sync vulnerabilities to your backlog
- **GitHub Issues**: Native integration

### 💰 Transparent Pricing
- **Trial**: 10 free credits (no credit card)
- **Pay-As-You-Go**: $29/month + usage
- **Pro**: $599/month (500 credits included)

## Quick Start

Get RSOLV running in 3 steps:

### 1. Get API Key
Visit [rsolv.dev](https://rsolv.dev) and sign up. You'll get 10 free trial credits.

### 2. Add Secret
In your GitHub repo: **Settings → Secrets → Actions → New repository secret**
- Name: `RSOLV_API_KEY`
- Value: Your API key from step 1

### 3. Add Workflow
Create `.github/workflows/rsolv.yml`:

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
          mode: scan  # Start with scan mode
```

That's it. Push to trigger your first scan.

## Example: SQL Injection Detection

Here's what RSOLV does when it finds a real SQL injection:

**1. Detects vulnerable code:**
```javascript
// Vulnerable: User input directly in SQL query
app.get('/user/:id', (req, res) => {
  const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
  db.query(query, (err, result) => res.json(result));
});
```

**2. Generates RED test proving the exploit:**
```javascript
test('SQL injection in user endpoint', async () => {
  // This test FAILS, proving the vulnerability
  const maliciousId = "1 OR 1=1";
  const res = await request(app).get(`/user/${maliciousId}`);

  // Attacker can extract all users, not just ID 1
  expect(res.body.length).toBe(1); // FAILS - returns ALL users
});
```

**3. Creates fix making test GREEN:**
```javascript
// Fixed: Parameterized query prevents injection
app.get('/user/:id', (req, res) => {
  const query = 'SELECT * FROM users WHERE id = ?';
  db.query(query, [req.params.id], (err, result) => res.json(result));
});
```

**4. Educates your team:**
Pull request includes:
- **What**: SQL injection via unsanitized user input
- **Why**: Direct string interpolation allows query manipulation
- **How to prevent**: Always use parameterized queries
- **References**: OWASP SQL Injection, CWE-89

## Why Test-First Matters

### Traditional Scanners
❌ Report potential issues based on patterns
❌ Can't prove vulnerabilities exist
❌ High false positive rate (60-80% in some tools)
❌ Teams lose trust, ignore findings

### RSOLV
✅ Proves vulnerabilities with executable tests
✅ Zero false positives (no test = no report)
✅ Builds team confidence in findings
✅ Educational: Tests demonstrate exploit scenarios

## Use Cases

### For Startups
- Ship secure code without hiring a security team
- Catch vulnerabilities before they reach production
- Build security credibility for enterprise sales

### For Enterprises
- Reduce security team workload (only real issues escalated)
- Enforce secure coding standards in CI/CD
- Compliance documentation (OWASP, SANS coverage)

### For Open Source
- Community trust: Transparent security testing
- Lower barrier: Contributors learn secure patterns
- Free tier available for qualifying projects

## What's Next?

RSOLV is live on the [GitHub Marketplace](https://github.com/marketplace/actions/rsolv) today.

We're starting small, building in public, and listening to early adopters.

**Planned features** (next 90 days):
- Custom security rules (bring your own patterns)
- IDE integration (VS Code, JetBrains)
- Enterprise SSO (Okta, Azure AD)
- Advanced reporting (compliance exports, trend analysis)

## Try It Now

**Install**: [GitHub Marketplace](https://github.com/marketplace/actions/rsolv)
**Docs**: [docs.rsolv.dev](https://docs.rsolv.dev)
**Support**: [support@rsolv.dev](mailto:support@rsolv.dev)

Start with 10 free trial credits. No credit card required.

---

## FAQ

**Q: How is this different from Snyk, Dependabot, or CodeQL?**

RSOLV focuses on custom code vulnerabilities, not dependency issues. It generates executable tests to prove vulnerabilities exist—most scanners just report potential issues without proof.

**Q: Will this work with my language/framework?**

Currently: JavaScript, TypeScript, Python, Ruby, Go, Java. Framework support includes Express, Django, Rails, Spring. More languages coming based on demand.

**Q: What about false negatives?**

No tool is perfect. RSOLV's 170+ patterns cover common vulnerabilities (OWASP Top 10, SANS Top 25). We're constantly adding patterns based on real-world findings.

**Q: How much does it cost?**

Trial: 10 free credits. Pay-as-you-go: $29/month + usage. Pro: $599/month (500 credits included). See [pricing](https://rsolv.dev/pricing) for details.

**Q: What data does RSOLV collect?**

We only collect anonymized usage metrics (counts, error rates). No code, no PII, no repo names. Opt-out available via `RSOLV_TELEMETRY=false`.

**Q: Can I contribute security patterns?**

Yes! We're building a community pattern library. Email [support@rsolv.dev](mailto:support@rsolv.dev) to discuss.

---

**Built by**: [@dylan](https://github.com/dylantknguyen) (RSOLV Founder)
**Follow**: [@rsolv@infosec.exchange](https://infosec.exchange/@rsolv) (Mastodon)
**Star us**: [github.com/RSOLV-dev/RSOLV-action](https://github.com/RSOLV-dev/RSOLV-action)
