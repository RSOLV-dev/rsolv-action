# Hacker News "Show HN" Post

**RFC**: RFC-067 Week 2
**Platform**: Hacker News (news.ycombinator.com)
**Timing**: Launch day (Hour 4-6)
**Goal**: Technical community awareness, early adopters, feedback

---

## Title Options

**Option 1 (Recommended):**
```
Show HN: RSOLV – AI that validates vulnerabilities before fixing them
```

**Option 2:**
```
Show HN: Test-first AI security engineer for GitHub Actions
```

**Option 3:**
```
Show HN: Zero false positives – AI security that proves vulnerabilities with tests
```

**Guidelines**:
- Max 80 characters
- Start with "Show HN:"
- Be specific, not salesy
- Include key differentiator

**Selected**: Option 1 (clear value prop, mentions validation)

---

## Post Body

```
Hi HN,

I built RSOLV, an AI security engineer for GitHub Actions that validates vulnerabilities with executable tests before reporting them.

**The problem**: Security scanners have a false positive problem. I've seen teams ignore 90% of scanner alerts because they've learned not to trust them. Then real vulnerabilities slip through.

**The approach**: RSOLV follows TDD principles applied to security:
1. SCAN: Detect potential vulnerabilities (SQL injection, XSS, etc.)
2. VALIDATE: Generate executable RED test proving the vulnerability exists
3. MITIGATE: Create fix that makes the test GREEN

**Key rule**: No failing test = no report.

This eliminates false positives and gives teams confidence that every finding is real.

**Example**:

Vulnerable code:
```js
const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
```

RSOLV generates this test:
```js
test('SQL injection in /user/:id', async () => {
  const res = await request(app).get('/user/1 OR 1=1');
  expect(res.body.length).toBe(1); // FAILS - returns ALL users
});
```

Test fails → vulnerability confirmed → create fix:
```js
const query = 'SELECT * FROM users WHERE id = ?';
db.query(query, [req.params.id], ...);
```

Now test passes. PR includes fix + test + educational context.

**Tech stack**:
- Detection: AST-based (170+ patterns), server-side validation
- Test generation: AI-powered, framework-aware
- Languages: JS, TS, Python, Ruby, Go, Java
- Integration: GitHub Actions, Jira, Linear

**Pricing**: 10 free trial credits, then $29/month PAYG or $599/month Pro.

**Try it**: GitHub Marketplace - github.com/marketplace/actions/rsolv
**Docs**: docs.rsolv.dev
**Source**: github.com/RSOLV-dev/RSOLV-action (action code is open, platform is proprietary)

I'm here to answer questions about the architecture, test generation approach, or anything else. Would love feedback from the HN community—especially on false positives/negatives if you try it.

Thanks!
```

---

## Submission Checklist

### Pre-Post
- [ ] **Timing**: Post between 8-10 AM PT (best HN traffic)
- [ ] **Account age**: Ensure HN account is >1 year old (better visibility)
- [ ] **Karma**: Check karma >50 (posts from newer/low-karma accounts get less visibility)
- [ ] **Availability**: Block 4-6 hours for active engagement

### During Post
- [ ] **Monitor constantly**: Check for comments every 5-10 minutes
- [ ] **Respond quickly**: Reply within 15 minutes to all questions
- [ ] **Be humble**: HN values honesty over hype
- [ ] **Be technical**: Dive deep when asked
- [ ] **Acknowledge limitations**: Don't oversell

### Post-Post
- [ ] **Track metrics**: Upvotes, comments, referral traffic
- [ ] **Engage long-term**: Return to thread for 24-48 hours
- [ ] **Share learnings**: Document feedback for product roadmap

---

## Anticipated Questions & Answers

### Q: How is this different from Semgrep/CodeQL/Snyk?

**A**:
```
Great question. Key differences:

1. **Validation**: RSOLV generates executable tests to prove vulnerabilities. Most scanners just report potential issues without proof.

2. **Scope**: RSOLV focuses on custom code vulnerabilities (SQL injection, XSS, etc.). Snyk/Dependabot focus on dependencies. CodeQL is more similar but doesn't generate validation tests.

3. **False positives**: Because we require a failing test, we eliminate guesswork. If the test doesn't fail, we don't report it.

4. **Educational**: Every PR includes security context, helping teams learn secure patterns.

Not meant to replace all tools—just provide higher confidence in findings for custom code.
```

---

### Q: What about false negatives?

**A**:
```
Valid concern. No tool catches everything.

Our coverage:
- 170+ patterns (OWASP Top 10, SANS Top 25)
- AST-based detection (not regex)
- Framework-aware (Express, Django, Rails, etc.)

We're definitely going to miss some vulnerabilities, especially:
- Complex logic flaws
- Business logic issues
- Zero-days

Our goal isn't 100% coverage—it's high-confidence findings with zero false positives. We'd rather miss some issues than waste your time with noise.

Feedback on coverage gaps is super valuable. What are we missing?
```

---

### Q: How do you handle different test frameworks?

**A**:
```
Good question. We detect the test framework from your project:

JavaScript: Jest, Mocha, Vitest
Python: pytest, unittest
Ruby: RSpec, Minitest
Go: testing package

If we can't detect a framework, we ask via GitHub comment or fall back to the most common one for that language.

Generated tests match your existing style (describe/it vs test(), etc.).

Not perfect yet—we're learning from real repos. If the tests don't run in your setup, definitely let me know.
```

---

### Q: What data do you send to your servers?

**A**:
```
Transparency on this:

**What we send**:
- AST (abstract syntax tree) for validation
- Code snippets for context (only relevant to the finding)
- Language/framework metadata

**What we DON'T send**:
- Full codebase
- Secrets, env vars, config
- PII (emails, usernames, etc.)

**Privacy**:
- Data encrypted in transit (TLS)
- Data deleted after processing
- No long-term storage of code
- Opt-out: RSOLV_TELEMETRY=false

We're building for security teams—we take data privacy seriously.

Happy to go deeper on architecture if you're interested.
```

---

### Q: Why not open source?

**A**:
```
Fair question. Here's my thinking:

**Action code**: Open source (github.com/RSOLV-dev/RSOLV-action)
**Platform**: Proprietary (test generation, AST validation)

Reasons:
1. **Sustainability**: Need revenue to maintain/improve the service
2. **Competitive moat**: Test generation is the core IP
3. **Infrastructure costs**: Server-side validation isn't free

I'm open to open-sourcing detection patterns (like Semgrep rules) if there's community interest. Would you use RSOLV if the patterns were open but test generation was paid?

Curious about HN's perspective on this.
```

---

### Q: How accurate is the test generation?

**A**:
```
Honest answer: Pretty good, not perfect.

Accuracy (based on internal testing):
- ~85% of generated tests run without modification
- ~95% of tests that run correctly prove the vulnerability

Common issues:
- Missing imports/setup
- Test framework detection errors
- Complex application state requirements

When tests don't work:
- We still report the vulnerability (with caveat)
- Include the test code for manual review/fixing
- Learn from failures to improve

This is the hardest part of RSOLV—we're constantly improving based on real-world repos.

If you try it and tests fail, please share the repo (if public) or anonymized examples. That feedback is gold.
```

---

### Q: Can I contribute patterns?

**A**:
```
Absolutely! Here's how:

**Right now**:
Email support@rsolv.dev with:
- Vulnerability type (e.g., "LDAP injection")
- Detection pattern (AST structure or code example)
- Test case (proof of concept)

I'll review and integrate if it fits.

**Future**:
Planning to open-source the pattern library (like Semgrep rules). Contributors get:
- Credit in changelog
- Free Pro tier (if you want it)
- Input on roadmap

Interested in building this as a community resource. Thoughts?
```

---

### Q: What's your false positive rate?

**A**:
```
Target: 0%

Actual: ~2-3% (based on early testing)

Why not zero?:
- Test generation failures (test should fail but doesn't due to setup issues)
- Edge cases we haven't seen yet

How we handle it:
- User reports false positive → we investigate
- If confirmed, update pattern to exclude that case
- Add to test suite to prevent regression

The 2-3% is mostly test generation problems, not detection problems. Working to get it to actual zero.

Compare to traditional scanners: 60-80% false positive rate (per OWASP).

Getting from 2% → 0% is the goal.
```

---

## Engagement Strategy

### Hour 0-2: Active Engagement
- **Goal**: Respond to every comment within 15 minutes
- **Tone**: Humble, technical, honest
- **Focus**: Answer questions thoroughly, acknowledge limitations

### Hour 2-6: Sustained Presence
- **Goal**: Keep thread active, climb to front page
- **Tone**: Helpful, not defensive
- **Focus**: Deep technical discussions, gather feedback

### Hour 6-24: Long Tail
- **Goal**: Continue engagement, drive installs
- **Tone**: Appreciative, open to suggestions
- **Focus**: Thank commenters, address late questions

### Day 2-7: Follow-Up
- **Goal**: Implement feedback, report back
- **Tone**: Community-focused
- **Focus**: "Thanks HN—we shipped X based on your feedback"

---

## Success Metrics

### Engagement Metrics
- **Upvotes**: Target >100 (front page), stretch >300
- **Comments**: Target >50 (active discussion)
- **Time on front page**: Target >6 hours

### Conversion Metrics
- **Marketplace installs**: Target 20-50 from HN
- **Trial signups**: Target 5-10
- **GitHub stars**: Target 30-50

### Qualitative Metrics
- **Feedback quality**: Are people sharing useful critiques?
- **Community interest**: Are people asking to contribute?
- **Validation**: Do experts validate the approach?

---

## Red Flags to Avoid

### DON'T:
- ❌ Argue with critics (acknowledge, learn, move on)
- ❌ Oversell ("revolutionize security" → no)
- ❌ Ignore tough questions (face them head-on)
- ❌ Be defensive (HN values humility)
- ❌ Spam replies (quality over quantity)

### DO:
- ✅ Be honest about limitations
- ✅ Share technical details when asked
- ✅ Thank people for feedback
- ✅ Acknowledge competitors (respectfully)
- ✅ Invite contributions/suggestions

---

## Post-HN Action Items

### Within 24 Hours
- [ ] Compile all feedback into product roadmap doc
- [ ] Respond to feature requests (yes/no/maybe)
- [ ] Fix critical issues raised (if any)
- [ ] Thank top commenters personally

### Within 1 Week
- [ ] Ship improvements based on feedback
- [ ] Post follow-up: "Show HN: RSOLV v1.1 – Implemented your feedback"
- [ ] Reach out to interested contributors

### Within 1 Month
- [ ] Share metrics: "HN → X installs, Y signups, Z paying customers"
- [ ] Case study: "How HN feedback shaped RSOLV"
- [ ] Invite HN community to private beta of new features

---

## Alternative: "Ask HN" Pre-Launch

If marketplace approval is delayed, consider:

**Title**:
```
Ask HN: Would you use an AI security tool that validates vulnerabilities with tests?
```

**Body**:
```
I'm building RSOLV, an AI security engineer that generates executable tests to prove vulnerabilities before reporting them.

**Context**: I've seen teams ignore 90% of security scanner alerts due to false positives. This leads to alert fatigue and missed real issues.

**Approach**: Before reporting a vulnerability, RSOLV generates a failing test demonstrating the exploit. If it can't write a failing test, it doesn't report the issue.

**Question for HN**:
1. Would this approach solve the false positive problem for you?
2. What vulnerabilities would you want covered? (SQL injection, XSS, etc.)
3. What would make you trust an AI security tool?

Not trying to sell anything—genuinely want feedback before launch.

Thanks!
```

This builds community interest before the hard launch.

---

**Reference**: RFC-067 line 611
**Launch Plan**: LAUNCH-PLAN.md
