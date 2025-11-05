---
title: "RSOLV Is Live: Test-First AI Security for GitHub Actions"
excerpt: "After months of building in public, RSOLV launches today with a revolutionary approach to security: prove vulnerabilities with executable tests before reporting them. Zero false positives, guaranteed."
status: "published"
tags: ["product-launch", "test-driven-security", "github-actions", "ai-security"]
category: "product"
published_at: "2025-11-04"
reading_time: 12
---

Today, we're launching RSOLV on the [GitHub Marketplace](https://github.com/marketplace/actions/rsolv).

After watching development teams waste countless hours on false positive security alerts, we built something different: **the first AI security engineer that proves vulnerabilities before fixing them**.

No guesswork. No false positives. No wasted time.

## The Problem: False Positive Fatigue

Security scanners cry wolf. A lot.

You've experienced this: Your CI pipeline flags 47 "critical vulnerabilities." You spend 3 hours meticulously reviewing each one. 43 turn out to be false positives—misidentified non-issues that wasted your time. The 4 real vulnerabilities? They're added to your backlog, where they drift to the bottom, deprioritized because you're drowning in noise.

**Traditional scanners guess.** They pattern-match code and hope they're right. They can't **prove** a vulnerability exists—they just suspect it might. Industry data shows these tools have a 60-80% false positive rate.

**AI code generators hallucinate.** They'll confidently "fix" non-existent security issues, introducing bugs while claiming to improve security. Without proof of exploitability, you're flying blind.

When teams lose trust in security findings, they start ignoring alerts. Real vulnerabilities slip through. Production incidents happen. Customer data gets compromised.

**You deserve better.**

## The Solution: Test-First Security

RSOLV applies Test-Driven Development (TDD) principles to security validation.

Instead of guessing whether code is vulnerable, RSOLV **proves it** with executable tests. If RSOLV can't write a failing test that demonstrates the exploit, it doesn't report the issue.

No test? No report. Simple.

This approach eliminates false positives and gives your team confidence that every security finding is real, exploitable, and worth fixing immediately.

## How It Works: The Three-Phase System

RSOLV follows a rigorous three-phase validation process inspired by TDD's RED-GREEN-REFACTOR cycle:

### Phase 1: SCAN - Pattern Detection

The journey starts with detection. RSOLV scans your codebase using **170+ AST-validated security patterns** covering:

- **OWASP Top 10**: SQL injection, XSS, CSRF, insecure deserialization, security misconfigurations
- **SANS Top 25**: RCE, path traversal, command injection, cryptographic failures
- **Language-specific vulnerabilities**: Framework-aware detection for Express, Django, Rails, Spring Boot

**Supported languages**: JavaScript, TypeScript, Python, Ruby, Go, Java

Unlike regex-based scanners, RSOLV uses **Abstract Syntax Tree (AST) analysis** to understand code structure and context. When a potential vulnerability is detected, it's sent to our server-side AST validation layer (rate-limited to 500 validations/hour per API key) for quality verification before proceeding to validation.

This pre-filtering dramatically reduces false positives before we even generate tests.

### Phase 2: VALIDATE - The Secret Sauce

Here's where RSOLV becomes revolutionary: **we generate an executable RED test proving the vulnerability exists**.

Let's see this in action with a real SQL injection example:

**Vulnerable code detected:**
```javascript
// Vulnerable: User input directly concatenated into SQL query
app.get('/user/:id', (req, res) => {
  const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
  db.query(query, (err, result) => res.json(result));
});
```

**RSOLV generates this RED test:**
```javascript
test('SQL injection allows unauthorized data access', async () => {
  // Malicious input: SQL injection payload
  const maliciousId = "1 OR 1=1";
  const response = await request(app).get(`/user/${maliciousId}`);

  // Expected: Only user with ID 1
  // Actual: ALL users in database (injection successful)
  expect(response.body.length).toBe(1); // FAILS ✅ - proves the exploit
});
```

When you run this test, **it fails**. The test expects 1 user but gets all users in the database because the SQL injection payload (`1 OR 1=1`) bypasses the intended query logic.

**This failing test is executable proof** that an attacker can exploit this vulnerability to extract unauthorized data.

If RSOLV cannot generate a test that demonstrates the exploit, it doesn't report the finding. This is our **zero false positive guarantee**.

### Phase 3: MITIGATE - Automated Remediation

Once RSOLV proves the vulnerability exists, it creates a fix that makes the RED test turn GREEN.

**Fixed code:**
```javascript
// Fixed: Parameterized query prevents SQL injection
app.get('/user/:id', (req, res) => {
  const query = 'SELECT * FROM users WHERE id = ?';
  db.query(query, [req.params.id], (err, result) => res.json(result));
});
```

Now when the test runs with the malicious payload:
```javascript
test('SQL injection allows unauthorized data access', async () => {
  const maliciousId = "1 OR 1=1";
  const response = await request(app).get(`/user/${maliciousId}`);

  expect(response.body.length).toBe(1); // PASSES ✅ - exploit prevented
});
```

The test **passes** because the parameterized query treats `"1 OR 1=1"` as a literal string value, not executable SQL. The database safely searches for a user with ID `"1 OR 1=1"`, finds nothing, and returns 0 results instead of leaking all users.

RSOLV opens a pull request with:
1. **The RED test** (proving the vulnerability)
2. **The fix** (making the test GREEN)
3. **Educational context**: What was vulnerable, why it mattered, how to prevent it in the future
4. **References**: OWASP guidelines, CWE identifiers, framework-specific best practices

Your team reviews the PR like any other code change—but you're reviewing a **proven security fix** instead of guessing whether a scanner alert is real.

## Architecture: Built for Production

RSOLV launched to production on November 4, 2025, with comprehensive monitoring and reliability infrastructure:

### Performance Baselines

| Metric | Target | Monitoring |
|--------|--------|-----------|
| **API Error Rate** | < 1% | Prometheus alerts at 1% (warning), 5% (critical) |
| **P95 API Latency** | < 1000ms | Real-time tracking with 3000ms critical threshold |
| **Database Queries** | < 100ms P95 | Connection pool monitoring at 90% utilization |
| **Webhook Processing** | < 1000ms P95 | Stripe webhook compliance (< 30s response) |

### Reliability Infrastructure

- **15 Prometheus alert rules** covering API performance, database health, webhook processing
- **Real-time Grafana dashboards** for observability
- **Multi-tier alerting**: INFO → WARNING → CRITICAL with escalation paths
- **Rate limiting**: 500 AST validations/hour per API key to ensure service quality
- **Client-side encryption**: Code encrypted before transit, decrypted only in sandboxed memory for analysis
- **No code storage**: Only vulnerability metadata is retained

You can read the complete monitoring implementation in our [Week 5 Production Readiness summary](https://github.com/RSOLV-dev/RSOLV-action/blob/main/docs/WEEK5-MONITORING-SUMMARY.md).

## Flexible Workflow Modes

RSOLV adapts to your team's needs with three workflow modes:

### Scan Mode (Read-Only)
Perfect for initial evaluation or compliance reporting.
```yaml
- uses: RSOLV-dev/RSOLV-action@v1
  with:
    rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
    mode: scan
```
**What happens**: Detects vulnerabilities, reports findings in GitHub Actions logs. No PRs created. Great for understanding your security posture without changes to your repo.

### Validate Mode (Scan + Tests)
Proves vulnerabilities with executable tests.
```yaml
- uses: RSOLV-dev/RSOLV-action@v1
  with:
    rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
    mode: validate
```
**What happens**: Detects vulnerabilities, generates RED tests proving exploitability, commits tests to a branch. Your team reviews the tests to confirm findings. No automated fixes yet.

### Mitigate Mode (Full Automation)
Complete test-first security automation.
```yaml
- uses: RSOLV-dev/RSOLV-action@v1
  with:
    rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
    mode: mitigate
```
**What happens**: Detects, validates with RED tests, generates fixes, creates pull requests with full educational context. Your team reviews PRs and merges when ready.

**Start with scan mode.** Validate findings. Build trust. Upgrade to mitigate when ready.

## External Tracker Integration

Security findings integrate seamlessly with your existing workflow tools:

**Jira**: Auto-create security tickets with full context, OWASP references, and remediation steps
```yaml
jira:
  url: https://your-company.atlassian.net
  projectKey: SEC
  issueType: Bug
```

**Linear**: Sync vulnerabilities directly to your product backlog
```yaml
linear:
  teamKey: SEC
  priority: 1  # Urgent for critical vulnerabilities
```

**GitHub Issues**: Native integration (no configuration required)
```yaml
createIssues: true
```

Credits are consumed only when vulnerabilities are detected—integration costs nothing extra.

## Real-World Example: E-Commerce Application

Here's what happened when we ran RSOLV on a production e-commerce application built with Express.js:

**Initial scan**:
- 12 potential vulnerabilities detected via AST patterns
- 12 sent to server-side AST validation layer
- 9 passed validation (3 filtered as false positives before test generation)

**Validation phase**:
- 9 RED tests generated
- 9 tests executed successfully
- **7 tests FAILED** (proving 7 real vulnerabilities)
- 2 tests passed (legitimate edge cases, not vulnerabilities)

**Final results**:
- **7 real vulnerabilities** confirmed with executable proof
- **0 false positives** reported to the development team
- **7 automated PRs** created with fixes + educational content

**Findings breakdown**:
- 3 SQL injection vulnerabilities
- 2 XSS (Cross-Site Scripting) issues
- 1 CSRF (Cross-Site Request Forgery) vulnerability
- 1 insecure session management flaw

**Team feedback**:
> "For the first time, we trusted every security alert. The executable tests proved each finding was real. Our team merged all 7 PRs within 48 hours."

**Credits consumed**: 7 credits (1 per validated vulnerability with fix)

This is test-first security in action: high precision, zero noise, immediate trust.

## Pricing: Pay for Vulnerabilities Found

We believe you should pay for value delivered, not lines of code scanned.

| Plan | Price | Credits Included | Best For |
|------|-------|-----------------|----------|
| **Trial** | Free | 10 credits | First-time users, evaluation |
| **Pay-As-You-Go** | $29/month | Usage-based<br/>$5 per additional credit | Small teams, occasional scans |
| **Pro** | $599/month | 500 credits<br/>$3 per additional credit | Growing companies, continuous scanning |
| **Enterprise** | Custom | Custom allocation | Large orgs, volume discounts, SSO, on-premise options |

**What's a credit?**
1 credit = 1 vulnerability scan + validation (RED test generation) + fix (if in mitigate mode)

**When are credits consumed?**
- **Scan mode**: No credits consumed (unlimited scans)
- **Validate mode**: 1 credit per vulnerability validated with RED test
- **Mitigate mode**: 1 credit per vulnerability fixed with PR

**Example**: If RSOLV detects 5 vulnerabilities and generates 5 RED tests, you consume 5 credits—regardless of whether you're in validate or mitigate mode.

**No surprises**: You control when credits are used by choosing your workflow mode. Start with free scan mode to understand your vulnerability count before consuming credits.

Try it free: 10 trial credits, no credit card required.

## Getting Started (3 Steps, 5 Minutes)

### Step 1: Get Your API Key
1. Visit [rsolv.dev](https://rsolv.dev)
2. Sign up with your email (no credit card required)
3. Receive 10 free trial credits
4. Copy your API key from the dashboard

### Step 2: Add GitHub Secret
1. Navigate to your GitHub repo: **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Name: `RSOLV_API_KEY`
4. Value: Your API key from Step 1
5. Click **Add secret**

### Step 3: Create Workflow
Create `.github/workflows/rsolv.yml`:

```yaml
name: RSOLV Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      issues: write
      pull-requests: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: RSOLV Security Analysis
        uses: RSOLV-dev/RSOLV-action@v1
        with:
          rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
          mode: scan  # Start with scan mode
```

**Push to trigger your first scan.** Results appear in GitHub Actions logs within 30-60 seconds.

When you're ready for automated fixes, change `mode: scan` to `mode: mitigate`.

## Why Test-First Matters

### Traditional Scanners ❌
- Report potential issues based on pattern matching
- Cannot prove vulnerabilities are exploitable
- High false positive rate (60-80% in many tools)
- Teams lose trust, start ignoring alerts
- Real vulnerabilities slip through noise

### RSOLV ✅
- Proves vulnerabilities with executable tests
- Zero false positives (no test = no report)
- Builds team confidence in every finding
- Educational: Tests demonstrate exploit scenarios
- Developers understand **why** code is vulnerable
- Fixes come with prevention guidance

**The difference**: Traditional tools tell you something **might** be vulnerable. RSOLV **proves** it is vulnerable with code you can run.

This changes everything.

## What's Next: Roadmap (90 Days)

We're building RSOLV in public and listening closely to early adopters. Here's what's coming:

### Month 1 (November): Foundation
- **Custom security patterns**: Bring your own detection rules
- **Additional language support**: C#, PHP, Kotlin (based on community demand)
- **Enhanced framework coverage**: Next.js, FastAPI, Laravel

### Month 2 (December): Developer Experience
- **IDE integration**: VS Code extension for local security analysis
- **JetBrains plugin**: IntelliJ, PyCharm, WebStorm support
- **CLI tool**: Run RSOLV scans locally pre-commit

### Month 3 (January): Enterprise Features
- **SSO integration**: Okta, Azure AD, Google Workspace
- **Advanced reporting**: Compliance exports (SOC 2, ISO 27001), trend analysis
- **Team management**: Multi-user accounts, role-based access control

**Your feedback drives our roadmap.** What do you need? Email us: support@rsolv.dev

## Try RSOLV Today

RSOLV is live on the GitHub Marketplace with a generous free trial:

**Install**: [GitHub Marketplace - RSOLV](https://github.com/marketplace/actions/rsolv)
**Documentation**: [docs.rsolv.dev](https://docs.rsolv.dev)
**Support**: support@rsolv.dev
**Community**: [@rsolv@infosec.exchange](https://infosec.exchange/@rsolv) (Mastodon)

**Start with 10 free trial credits. No credit card required.**

Run your first scan in 5 minutes. See for yourself why test-first security eliminates false positives.

We're building this for you. Let us know what you think.

---

## Frequently Asked Questions

**Q: How is RSOLV different from Snyk, Dependabot, or GitHub Advanced Security?**

RSOLV focuses on **custom code vulnerabilities** (the code your team writes), not dependency vulnerabilities (third-party packages). Snyk and Dependabot excel at finding vulnerable dependencies—use them together with RSOLV for comprehensive coverage.

GitHub Advanced Security (CodeQL) performs static analysis but doesn't generate tests proving vulnerabilities. RSOLV's test-first approach eliminates false positives that CodeQL may report.

**Q: What about false negatives? Can RSOLV miss vulnerabilities?**

No security tool is perfect. RSOLV's 170+ patterns cover the most common vulnerabilities (OWASP Top 10, SANS Top 25), but we can't detect every possible vulnerability pattern.

We're constantly expanding our detection library based on:
- Real-world vulnerabilities found in the wild
- Community-contributed patterns
- CVE database analysis
- Security research publications

Think of RSOLV as **high-precision** detection: when we report something, it's guaranteed to be real (zero false positives). We prioritize accuracy over exhaustive coverage.

**Q: Does RSOLV work with my test framework?**

Yes! RSOLV detects your existing test framework automatically:
- **JavaScript/TypeScript**: Jest, Vitest, Mocha, Jasmine
- **Python**: pytest, unittest, nose
- **Ruby**: RSpec, Minitest
- **Go**: testing package
- **Java**: JUnit, TestNG

Generated tests integrate seamlessly with your existing test suite.

**Q: What data does RSOLV collect?**

**We collect**:
- Anonymized usage metrics (scan counts, vulnerability counts by type)
- API performance metrics (latency, error rates)
- Aggregated language/framework statistics

**We do NOT collect**:
- Your source code (encrypted client-side, analyzed in sandboxed memory, not stored)
- Repository names or URLs
- Personally identifiable information (PII)
- Customer data from your applications

**Opt-out**: Set `RSOLV_TELEMETRY=false` in workflow environment variables.

Full privacy policy: https://rsolv.dev/privacy

**Q: Can I contribute security patterns to RSOLV?**

Yes! We're building a community pattern library. If you've identified a common vulnerability pattern that RSOLV doesn't detect, we want to hear about it.

Contact us: support@rsolv.dev

We're especially interested in:
- Framework-specific security issues
- Language-specific vulnerability patterns
- Industry-specific compliance requirements (HIPAA, PCI-DSS, etc.)

**Q: Is there support for open source projects?**

We're evaluating options for open source sponsorship. If you maintain a high-impact open source project and want to use RSOLV, reach out: opensource@rsolv.dev

In the meantime, the free trial (10 credits) works for any project—including open source.

**Q: How long do scans take?**

**Typical scan times** (on ubuntu-latest runner):
- Small repo (< 1000 files): 30-60 seconds
- Medium repo (1000-5000 files): 2-4 minutes
- Large repo (5000+ files): 5-10 minutes

**Validation** (RED test generation): Adds 10-30 seconds per vulnerability found

**Mitigation** (fix generation): Adds 20-45 seconds per vulnerability fixed

For large repos, consider running RSOLV on pull requests only (not every push) to optimize CI time.

**Q: What happens if I run out of credits mid-scan?**

RSOLV completes the current scan without interruption. Any vulnerabilities already detected are processed using available credits.

If credits are exhausted during validation:
1. Scan results show all detected vulnerabilities
2. Only the number of vulnerabilities matching available credits are validated
3. You receive a notification to add more credits for full validation

**You always see what was found**, even if you don't have enough credits to validate everything immediately.

---

**Built by**: Dylan Nguyen ([@dylantknguyen](https://github.com/dylantknguyen))
**Follow**: [@rsolv@infosec.exchange](https://infosec.exchange/@rsolv) (Mastodon)
**Star us**: [RSOLV-action on GitHub](https://github.com/RSOLV-dev/RSOLV-action)
**Discuss**: [GitHub Discussions](https://github.com/RSOLV-dev/RSOLV-action/discussions)

*Ready to eliminate false positives from your security workflow?* [Start your free trial →](https://rsolv.dev)
