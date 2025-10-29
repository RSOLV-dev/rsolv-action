# RSOLV Frequently Asked Questions (FAQ)

**Last Updated**: 2025-10-26
**Version**: 1.0
**Target Audience**: Prospective users, trial users, paying customers

---

## Table of Contents

1. [General](#general)
2. [Installation & Setup](#installation--setup)
3. [Features & Functionality](#features--functionality)
4. [Pricing & Billing](#pricing--billing)
5. [Security & Privacy](#security--privacy)
6. [Technical Details](#technical-details)
7. [Troubleshooting](#troubleshooting)
8. [Comparison to Other Tools](#comparison-to-other-tools)

---

## General

### What is RSOLV?

RSOLV is an AI security engineer for GitHub Actions that validates vulnerabilities with executable tests before reporting them. Unlike traditional scanners that guess, RSOLV proves every finding with a failing test.

### How does RSOLV work?

RSOLV follows a test-first methodology:
1. **SCAN**: Detect potential vulnerabilities using 170+ AST-validated patterns
2. **VALIDATE**: Generate executable RED test proving the vulnerability exists
3. **MITIGATE**: Create fix that makes the test GREEN

If RSOLV can't write a failing test, it doesn't report the issue.

### What makes RSOLV different from other security scanners?

**Key differences**:
- **Zero false positives**: Every finding validated with an executable test
- **Educational**: PRs include security context and prevention tips
- **Test-first**: Follows TDD principles applied to security
- **Custom code focus**: Detects vulnerabilities in your code, not just dependencies

Traditional scanners pattern-match and hope they're right. RSOLV proves vulnerabilities before reporting them.

### What vulnerability types does RSOLV detect?

**OWASP Top 10**:
- SQL Injection
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Insecure Authentication
- Security Misconfiguration
- Sensitive Data Exposure
- XML External Entities (XXE)
- Broken Access Control
- Security Logging Failures
- Server-Side Request Forgery (SSRF)

**Additional patterns** (170+ total):
- Remote Code Execution (RCE)
- Path Traversal
- Command Injection
- LDAP Injection
- Cryptographic Failures
- Insecure Deserialization
- Weak Randomness
- And more...

### What languages and frameworks are supported?

**Languages**:
- JavaScript (Node.js)
- TypeScript
- Python
- Ruby
- Go
- Java

**Frameworks** (framework-aware detection):
- Express.js (Node.js)
- Django, Flask (Python)
- Rails, Sinatra (Ruby)
- Gin, Echo (Go)
- Spring Boot (Java)

More languages/frameworks added based on user demand.

---

## Installation & Setup

### How do I install RSOLV?

**3-step installation**:

1. **Get API key**: Visit [rsolv.dev](https://rsolv.dev) and sign up
2. **Add secret**: In your GitHub repo, go to **Settings → Secrets → Actions → New repository secret**
   - Name: `RSOLV_API_KEY`
   - Value: Your API key from step 1
3. **Add workflow**: Create `.github/workflows/rsolv.yml`:

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

Push to trigger your first scan.

### How long does installation take?

**< 5 minutes** for most repos.

Breakdown:
- Get API key: 1-2 minutes
- Add secret: 30 seconds
- Add workflow: 1-2 minutes
- First scan: 1-3 minutes (depends on repo size)

### Do I need to install anything on my local machine?

No. RSOLV runs entirely in GitHub Actions. No local installation required.

### Can I use RSOLV with private repositories?

Yes. RSOLV works with both public and private repositories. Your code privacy is protected (see [Security & Privacy](#security--privacy)).

### What GitHub permissions does RSOLV need?

**Required**:
- `contents: read` - Read repository code
- `issues: write` - Create issues for findings (if enabled)
- `pull-requests: write` - Create PRs with fixes (mitigate mode)

**Default**: The action automatically uses `${{ github.token }}` with appropriate permissions.

---

## Features & Functionality

### What are the different workflow modes?

**Scan mode** (default):
- Detect vulnerabilities
- Report findings in workflow output
- No PR/issue creation
- **Best for**: First-time users, read-only scans

**Validate mode**:
- Scan + generate RED tests
- Prove vulnerabilities with executable tests
- No automated fixes
- **Best for**: Manual review before fixing

**Mitigate mode**:
- Scan + validate + create fix PRs
- Full automation
- **Best for**: Trusted repos, high confidence in findings

### How do I change modes?

Update your workflow file:

```yaml
- uses: RSOLV-dev/RSOLV-action@v1
  with:
    rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
    mode: mitigate  # Change this: scan, validate, or mitigate
```

### Can RSOLV create issues in external trackers?

Yes. RSOLV integrates with:
- **Jira**
- **Linear**
- **GitHub Issues** (native)

**Example (Jira)**:
```yaml
- uses: RSOLV-dev/RSOLV-action@v1
  with:
    rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
    jiraProject: SEC
    jiraToken: ${{ secrets.JIRA_TOKEN }}
```

See [docs.rsolv.dev](https://docs.rsolv.dev) for full integration guide.

### What information is included in RSOLV PRs?

**Every PR includes**:
1. **Vulnerability summary**: What was found
2. **RED test**: Executable test proving the issue
3. **Fix**: Code changes making test GREEN
4. **Educational context**:
   - Why this is vulnerable
   - How to prevent in future
   - OWASP/CWE references
5. **Prevention tips**: Best practices for your team

### Can I customize detection patterns?

**Currently**: No. Detection patterns are maintained by RSOLV.

**Planned**: Custom rules in enterprise tier (Q2 2026).

**Workaround**: Email support@rsolv.dev with pattern requests. We'll prioritize based on demand.

### Does RSOLV work with monorepos?

Yes. RSOLV scans the entire repository, including multiple projects/services.

**Performance tip**: Use `paths` filter to scan specific directories:
```yaml
on:
  push:
    paths:
      - 'services/api/**'  # Only scan API service
```

### Can I exclude certain files or directories?

Yes. Use `.rsolvignore` file (similar to `.gitignore`):

```
# .rsolvignore
node_modules/
test/fixtures/
*.test.js
```

---

## Pricing & Billing

### How much does RSOLV cost?

**Trial**: 10 free credits (no credit card required)

**Pay-As-You-Go**: $29/month + usage
- $29 base fee
- $5 per credit beyond included amount

**Pro**: $599/month
- 500 credits included
- $3 per additional credit
- Priority support

See [rsolv.dev/pricing](https://rsolv.dev/pricing) for details.

### What is a "credit"?

1 credit = 1 vulnerability scan + validation + mitigation (if applicable)

**Examples**:
- Scan mode: 1 credit per scan (no fixes)
- Validate mode: 1 credit per scan + test generation
- Mitigate mode: 1 credit per scan + test + fix PR

**Note**: Credits are consumed only when vulnerabilities are detected, not for clean scans.

### How many credits will I use?

**Depends on**:
- Repository size
- Vulnerability count
- Scan frequency

**Typical usage**:
- Small repo (< 10k LOC): 5-10 credits/month
- Medium repo (10k-50k LOC): 20-50 credits/month
- Large repo (> 50k LOC): 100+ credits/month

**Start with trial** to estimate your usage.

### Can I upgrade/downgrade my plan?

Yes. Change plans anytime from your account dashboard.

**Prorated billing**: Pay only for time used at each tier.

### What happens if I run out of credits?

**Options**:
1. **Auto-recharge**: Add credits automatically (configure in dashboard)
2. **Manual purchase**: Buy credits as needed
3. **Upgrade plan**: Switch to higher tier

**Scans pause** if credits run out (no surprise charges).

### Is there a discount for open source projects?

**Coming soon**: Free tier for qualifying open source projects.

**Requirements** (draft):
- Public repository
- OSI-approved license
- Active development (commits in last 6 months)

Email support@rsolv.dev to request early access.

### Do you offer enterprise pricing?

Yes. Contact support@rsolv.dev for:
- Volume discounts
- Custom SLA
- On-premise deployment
- SSO integration (Okta, Azure AD)

---

## Security & Privacy

### What data does RSOLV collect?

**What we send to servers**:
- Abstract Syntax Tree (AST) for validation
- Code snippets relevant to findings
- Language/framework metadata

**What we DON'T send**:
- Full codebase
- Secrets, environment variables, config files
- PII (emails, usernames, etc.)
- Proprietary business logic (only security-relevant code)

### How is my data protected?

**In transit**:
- TLS encryption (HTTPS only)

**At rest**:
- Encrypted storage (AES-256)
- Data deleted after processing (no long-term storage)

**Access control**:
- No human access to code (automated processing only)
- SOC 2 Type II certification (in progress)

### Can I opt out of telemetry?

Yes. Set `RSOLV_TELEMETRY=false` in your workflow:

```yaml
- uses: RSOLV-dev/RSOLV-action@v1
  env:
    RSOLV_TELEMETRY: false
```

**What telemetry tracks** (when enabled):
- Anonymized usage metrics (scan counts, error rates)
- No code, no PII, no repo names

### Is RSOLV SOC 2 compliant?

**In progress**. Expected completion: Q2 2026.

Current security measures:
- Encrypted data in transit/at rest
- No long-term code storage
- Regular security audits
- Penetration testing (quarterly)

### Where is data processed?

**Primary region**: US-East (AWS)

**Coming soon**: EU region option (GDPR compliance)

### What is RSOLV's vulnerability disclosure policy?

**Found a security issue in RSOLV?**

Email: security@rsolv.dev

**We commit to**:
- Acknowledge within 24 hours
- Initial assessment within 72 hours
- Fix critical issues within 7 days
- Public disclosure after fix (with your permission)

---

## Technical Details

### How does AST validation work?

**AST (Abstract Syntax Tree)** is a code representation used by compilers.

**RSOLV's approach**:
1. Parse code into AST (language-specific parser)
2. Analyze AST for vulnerability patterns
3. Validate findings server-side (not regex-based)
4. Generate tests based on AST structure

**Benefits**:
- Fewer false positives (understands code semantics)
- Framework-aware (knows Express vs. raw Node.js)
- Language-agnostic (same approach for all languages)

### What is the rate limit for AST validation?

**500 requests/hour per API key**

**Why?**:
- Server-side validation is compute-intensive
- Prevents abuse
- Ensures quality for all users

**If you hit the limit**:
- Scans queue and retry automatically
- No failed scans (just delayed)
- Upgrade to Pro for higher limits

### How accurate is test generation?

**Current accuracy** (based on internal testing):
- ~85% of tests run without modification
- ~95% of tests that run correctly prove the vulnerability

**Common issues**:
- Missing imports/setup code
- Test framework detection errors
- Complex application state requirements

**We're improving**: Accuracy increases with every real-world repo we process.

### Can I run RSOLV tests locally?

Yes. Generated tests are standard unit tests:

```bash
# JavaScript/TypeScript
npm test

# Python
pytest

# Ruby
rspec

# Go
go test
```

Tests are included in PRs—run them in your CI/CD pipeline.

### Does RSOLV support monorepo tools (Nx, Turborepo, etc.)?

Yes. RSOLV scans the entire repository structure, regardless of monorepo tool.

**Performance tip**: Use path filters to scan specific packages:
```yaml
paths:
  - 'packages/api/**'
  - 'packages/web/**'
```

### What if RSOLV generates a test that doesn't run?

**Report it**:
1. Open issue: [github.com/RSOLV-dev/RSOLV-action/issues](https://github.com/RSOLV-dev/RSOLV-action/issues)
2. Include:
   - Language/framework
   - Error message
   - Anonymized test code (if possible)

**We'll**:
- Investigate within 48 hours
- Fix test generation for that pattern
- Add to regression suite

This feedback is invaluable—thank you!

---

## Troubleshooting

### RSOLV is not detecting vulnerabilities in my repo. Why?

**Possible reasons**:
1. **No vulnerabilities**: Your code might be secure!
2. **Unsupported language**: Check [supported languages](#what-languages-and-frameworks-are-supported)
3. **Pattern coverage**: We might not have patterns for your specific issue
4. **Excluded files**: Check `.rsolvignore`

**Debug steps**:
1. Run scan mode on a known-vulnerable repo (e.g., [nodegoat](https://github.com/RSOLV-dev/nodegoat-vulnerability-demo))
2. Check workflow logs for errors
3. Email support@rsolv.dev with repo details (if public)

### RSOLV created a PR but the fix doesn't work. What should I do?

**Steps**:
1. **Review the test**: Does it prove the vulnerability?
2. **Check the fix**: Does it make the test pass locally?
3. **Report issue**: [GitHub issues](https://github.com/RSOLV-dev/RSOLV-action/issues)

**Include**:
- Language/framework
- Vulnerability type
- Error message (if any)

We'll investigate and improve fix generation.

### RSOLV reported a false positive. How do I report it?

**If you're certain it's a false positive**:
1. Open issue: [GitHub issues](https://github.com/RSOLV-dev/RSOLV-action/issues)
2. Include:
   - Code snippet
   - Why it's not vulnerable
   - Generated test (if available)

**We'll**:
- Investigate within 24 hours
- Update pattern to exclude that case
- Add to test suite (prevent regression)

False positive reports help us maintain our zero-false-positive goal.

### My workflow is failing with "Rate limit exceeded". What should I do?

**Cause**: You've hit the 500/hour AST validation limit.

**Solutions**:
1. **Wait**: Limit resets every hour
2. **Reduce scan frequency**: Scan on PR only, not every push
3. **Upgrade**: Pro plan has higher limits

**Workflow adjustment**:
```yaml
on:
  pull_request:  # Only scan PRs, not every push
    types: [opened, synchronize]
```

### RSOLV is taking a long time to scan. Is this normal?

**Scan time depends on**:
- Repository size
- Number of files
- Language complexity

**Typical times**:
- Small repo (< 1k LOC): 30-60 seconds
- Medium repo (1k-10k LOC): 1-3 minutes
- Large repo (> 10k LOC): 3-10 minutes

**If scan exceeds 15 minutes**:
- Check workflow logs for errors
- Ensure repo is within supported size (< 100k LOC)
- Contact support@rsolv.dev

### How do I get help if my issue isn't listed here?

**Support channels**:
1. **Documentation**: [docs.rsolv.dev](https://docs.rsolv.dev)
2. **GitHub Issues**: [RSOLV-action issues](https://github.com/RSOLV-dev/RSOLV-action/issues)
3. **Email**: support@rsolv.dev (response within 24 hours)
4. **Community**: [GitHub Discussions](https://github.com/RSOLV-dev/RSOLV-action/discussions)

**Pro/Enterprise**: Priority support with <4 hour response time.

---

## Comparison to Other Tools

### How is RSOLV different from Snyk?

**Snyk**: Dependency vulnerability scanner
- Focus: Known vulnerabilities in dependencies (npm, pip, etc.)
- Approach: Database of CVEs

**RSOLV**: Custom code vulnerability scanner
- Focus: Vulnerabilities in your code (SQL injection, XSS, etc.)
- Approach: Test-first validation

**Use both**: Snyk for dependencies, RSOLV for custom code.

### How is RSOLV different from GitHub CodeQL?

**CodeQL**: Static analysis for custom code
- Focus: Pattern-based detection
- Approach: Query language for code analysis
- Limitation: Can report false positives (no validation)

**RSOLV**: Test-validated security scanner
- Focus: Validated vulnerabilities only
- Approach: Generate executable tests proving issues
- Benefit: Zero false positives (requires proof)

**Overlap**: Both scan custom code. RSOLV adds test validation.

### How is RSOLV different from Semgrep?

**Semgrep**: Fast pattern-based scanner
- Focus: Custom rules, broad coverage
- Approach: Regex-like pattern matching
- Limitation: False positives (no runtime validation)

**RSOLV**: Test-first security scanner
- Focus: High-confidence findings
- Approach: AST + executable test generation
- Benefit: Proves vulnerabilities before reporting

**Use case difference**: Semgrep for broad coverage, RSOLV for high-confidence findings.

### How is RSOLV different from Dependabot?

**Dependabot**: Dependency update automation
- Focus: Keep dependencies up-to-date
- Approach: Monitor dependency releases, create PRs

**RSOLV**: Security vulnerability detection/fixing
- Focus: Find and fix vulnerabilities in custom code
- Approach: Scan → Validate → Mitigate

**Complementary**: Use Dependabot for dependency updates, RSOLV for custom code security.

### Can I use RSOLV alongside other security tools?

**Yes!** RSOLV complements existing tools:

**Recommended stack**:
- **RSOLV**: Custom code vulnerabilities (validated findings)
- **Snyk/Dependabot**: Dependency vulnerabilities
- **CodeQL/Semgrep**: Broad coverage (accept some false positives)
- **Manual review**: Complex logic, business rules

Each tool has strengths—use the right tool for the job.

---

## Contributing & Community

### Can I contribute to RSOLV?

**Yes!** We welcome:
- **Pattern contributions**: Suggest new vulnerability patterns
- **Test cases**: Share vulnerable code examples
- **Documentation**: Improve docs, FAQs, tutorials
- **Bug reports**: Help us improve quality

**How to contribute**:
1. Check [CONTRIBUTING.md](https://github.com/RSOLV-dev/RSOLV-action/blob/main/CONTRIBUTING.md)
2. Open issue or PR
3. Join [GitHub Discussions](https://github.com/RSOLV-dev/RSOLV-action/discussions)

### Is there a community forum?

**Yes**: [GitHub Discussions](https://github.com/RSOLV-dev/RSOLV-action/discussions)

**Topics**:
- Feature requests
- Use case discussions
- Best practices
- Showcase (share your RSOLV success stories)

### How do I stay updated on new features?

**Channels**:
- **GitHub Releases**: [RSOLV-action releases](https://github.com/RSOLV-dev/RSOLV-action/releases)
- **Blog**: [rsolv.dev/blog](https://rsolv.dev/blog)
- **Mastodon**: [@rsolv@infosec.exchange](https://infosec.exchange/@rsolv)
- **Email**: Monthly newsletter (opt-in during signup)

### Can I request a feature?

**Absolutely!**

**How**:
1. Open [feature request](https://github.com/RSOLV-dev/RSOLV-action/issues/new?template=feature_request.md)
2. Describe use case, expected behavior
3. Community votes (👍) help us prioritize

**Roadmap**: [rsolv.dev/roadmap](https://rsolv.dev/roadmap)

---

## Appendix

### Glossary

**AST (Abstract Syntax Tree)**: Code representation used by compilers/parsers

**RED test**: Failing test proving a vulnerability exists (TDD terminology)

**GREEN test**: Passing test after fix is applied

**False positive**: Scanner reports vulnerability that doesn't exist

**False negative**: Scanner misses real vulnerability

**OWASP Top 10**: Most critical web application security risks

**SANS Top 25**: Most dangerous software errors

**TDD (Test-Driven Development)**: Write failing test → write code → make test pass

### Further Reading

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [SANS Top 25](https://www.sans.org/top25-software-errors/)
- [CWE (Common Weakness Enumeration)](https://cwe.mitre.org/)
- [RSOLV Documentation](https://docs.rsolv.dev)

---

**Last Updated**: 2025-10-26
**Feedback**: support@rsolv.dev
**Report Issue**: [GitHub Issues](https://github.com/RSOLV-dev/RSOLV-action/issues)
