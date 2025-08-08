# RSOLV Demo Video Script

**Duration**: ~12 minutes edited (from 30-45 min recording)  
**Focus**: What actually works, no fake features  
**Tone**: Professional, excited about security automation

## Quick Recording Checklist
- [ ] Demo repo created with vulnerabilities
- [ ] RSOLV API key tested and working
- [ ] Browser cache cleared
- [ ] Screen recording software ready
- [ ] This script visible for reference

---

## Opening (30 seconds)

"Today I'm demonstrating RSOLV on NodeGoat - OWASP's deliberately vulnerable Node.js application used by security professionals worldwide for training.

If RSOLV can automatically fix these intentionally complex vulnerabilities, imagine what it can do for your production code."

---

## Part 1: The Problem (1 minute)

[Show app/data/allocations-dao.js:78]

"Here's NodeGoat's allocations DAO with a critical NoSQL injection. Line 78 uses MongoDB's dangerous $where operator with user input - this allows arbitrary JavaScript execution on your database server.

Finding these vulnerabilities manually is time-consuming. Fixing them correctly requires security expertise. And ensuring they stay fixed as code evolves is an ongoing challenge.

Let me show you how RSOLV automates this entire process."

---

## Part 2: How RSOLV Works (1 minute)

[Navigate to Actions tab]

"RSOLV integrates seamlessly with GitHub - no CLI or special tools needed.

Customers use RSOLV through two simple workflows:
1. Security Scan - Detects all vulnerabilities in your codebase
2. Fix Issues - Generates production-ready fixes for specific vulnerabilities

Everything happens through the GitHub interface your team already knows.

Let me show you the customer experience."

---

## Part 3: Triggering a Vulnerability Scan (2 minutes)

[Already on Actions tab]

"Let's start by scanning this codebase. This is exactly what a customer would do.

[Click 'RSOLV Security Scan' workflow]

I'll click on the Security Scan workflow...

[Click 'Run workflow' dropdown, then green 'Run workflow' button]

...and simply click Run workflow. That's it - no configuration needed.

[Click into the running workflow]

RSOLV is now scanning every file for vulnerabilities. It uses AST parsing to understand the code structure and eliminate false positives.

This typically takes 2-3 minutes for a codebase this size."

---

## Part 4: Detection Results (2 minutes)

[Click Issues tab after scan completes]

"The scan has completed. Look at what RSOLV found.

[Show list of issues]

RSOLV detected multiple vulnerabilities across the codebase. Notice these aren't false positives - RSOLV uses AST validation to ensure accuracy.

[Click on NoSQL injection issue]

Let's focus on this critical NoSQL injection. Look at the comprehensive details:
- Exact location: file and line number
- Proof of concept showing how to exploit it
- Business impact if exploited
- CVSS severity rating

[Click the file link to show actual code]

Here's the actual vulnerability - MongoDB's $where operator with user input.

[Go back to issue]

Now let's fix this specific vulnerability."

---

## Part 5: Live Fix Generation (3 minutes)

[On the NoSQL issue page]

"Now I'll trigger RSOLV to fix this specific vulnerability. Watch how simple this is.

[Click Labels gear icon in right sidebar]

I just click on Labels...

[Type 'rsolv:automate' and select it]

...and add the 'rsolv:automate' label. That's it.

[Click Actions tab]

RSOLV is now generating a fix for this specific issue. It's using Claude's AI to:
- Understand the vulnerability in context
- Generate a secure fix following best practices
- Add comprehensive tests
- Create educational documentation

[Click into the running workflow to show logs]

You can see the progress in real-time. This takes about 10-15 minutes.

[Speed up/cut to completion]

## Part 6: Reviewing the Generated Pull Request (3 minutes)

[Click Pull requests tab]

"The fix is complete. Let's review what RSOLV generated.

[Click on the newly created PR]

Here's the pull request. Notice several things:

First, the comprehensive description explains exactly what was vulnerable and why.

[Click 'Files changed' tab]

In the code changes, RSOLV replaced the dangerous $where clause with safe MongoDB operators - using proper parameterized queries like { userId: parsedUserId, stocks: { $gt: parsedThreshold } }.

[Scroll down to show tests]

[Show test section if present]

It also added tests to ensure the vulnerability can't resurface.

[Click back to 'Conversation' tab and scroll to educational section]

And here's what sets RSOLV apart - educational explanations that help your team understand:
- What the vulnerability was
- How the fix prevents it
- Best practices going forward

This isn't just fixing code - it's improving your team's security knowledge.

Notice that we scanned and found many vulnerabilities, but we're fixing them one at a time. This gives your team control over what gets fixed and when."

---

## Part 6: The Value Proposition (2 minutes)

[Back to repo main page]

"Let's talk about what this means for your team:

**Time Savings**: What takes a security expert hours, RSOLV does automatically.

**Consistency**: Every fix follows security best practices.

**Education**: Your developers learn secure coding patterns from every PR.

**Coverage**: RSOLV finds vulnerabilities that manual reviews might miss.

**Integration**: Works with your existing GitHub workflow - no new tools to learn."

---

## Part 7: Technical Depth (1 minute)

"The fact that RSOLV can fix OWASP's NodeGoat demonstrates real capability:

- NodeGoat is the industry standard for security training
- These vulnerabilities are intentionally complex
- RSOLV uses AST parsing and Claude's AI to understand context
- Fixes follow MongoDB and OWASP best practices
- If it can handle NodeGoat, it can handle your production code

This isn't a toy demo - it's fixing real vulnerabilities used to train security professionals."

---

## Closing (30 seconds)

"RSOLV transforms security from a bottleneck into an automated workflow.

We're currently in early access, working with select teams to refine the technology.

If you're interested in automated security fixes for your codebase, reach out to learn more about getting access.

Thanks for watching!"

---

## B-Roll and Editing Notes

### Speed Up:
- Workflow execution (show progress bar)
- Log scrolling
- Waiting periods

### Highlight:
- Vulnerable code lines
- Fixed code comparisons
- Test additions
- Educational content

### Add in Post:
- Annotations pointing out key features
- Timer showing processing speed
- Before/after code comparisons
- Security impact callouts

---

## Key Messages (Stay Honest):

✅ **DO Say:**
- "Works entirely through GitHub's web interface"
- "Scans find multiple vulnerabilities with AST validation"
- "Fix vulnerabilities one at a time with full control"
- "Uses Claude's advanced AI for fixes"
- "Includes tests and documentation"
- "Currently in early access"

❌ **DON'T Say:**
- "Sign up for free trial" (no signup system)
- "Check your dashboard" (doesn't exist)
- "View billing/usage" (not implemented)
- "Only pay for merged PRs" (no payment system)

---

## If Asked About Access:

"We're in early access, working closely with development teams to ensure RSOLV meets real-world needs. If you're interested, reach out and we'll discuss getting you set up with an API key."

---

## Technical Details to Have Ready:

- Supports JavaScript, TypeScript, Python, Ruby
- Covers OWASP Top 10 vulnerabilities
- Uses GitHub Actions for automation
- Powered by Claude AI
- Generates tests in appropriate framework

---

## This Demo Shows REAL Value:

No fake features needed - the core technology is impressive:
1. **It actually works** - finds real vulnerabilities
2. **Quality fixes** - not just find/replace
3. **Educational value** - teaches security
4. **GitHub native** - fits existing workflow
5. **AI-powered** - leverages Claude's capabilities

**Focus on what EXISTS and it's a strong demo!**