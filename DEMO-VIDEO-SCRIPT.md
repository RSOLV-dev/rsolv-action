# RSOLV Demo Video Script

**Duration**: 10-12 minutes  
**Setup Time**: 30 minutes pre-recording preparation  
**Tone**: Professional, excited about security automation

## Quick Recording Checklist
- [ ] Demo repo created with vulnerabilities
- [ ] RSOLV API key tested and working
- [ ] Browser cache cleared
- [ ] Screen recording software ready
- [ ] This script visible for reference

---

## Opening (30 seconds)

"Hi, I'm demonstrating RSOLV - the AI-powered security platform that automatically finds and fixes vulnerabilities in your code.

Today I'll show you how RSOLV can transform your security workflow - from detecting vulnerabilities with 90% fewer false positives, to automatically generating secure fixes that follow best practices.

Let's see it in action."

---

## Part 1: The Problem (45 seconds)

[Show vulnerable code on screen]

"Here's a typical Node.js application. Like many apps, it has security vulnerabilities hiding in the code. 

This SQL injection vulnerability [highlight line] could allow attackers to steal your entire database. 

This XSS vulnerability [highlight line] could let hackers inject malicious scripts.

Finding these manually takes hours. Fixing them correctly takes expertise. And keeping them fixed as code evolves? Nearly impossible.

That's where RSOLV comes in."

---

## Part 2: Quick Setup (1 minute)

[Show RSOLV dashboard]

"Getting started with RSOLV takes just minutes.

First, I'll sign up for early access on rsolv.dev. 

[Show email signup]

Now I can access my dashboard and get my API key.

[Copy API key]

Let me add this to my GitHub repository...

[Show GitHub secrets page]

And add the RSOLV workflow...

[Show workflow file]

This workflow will scan weekly and automatically fix issues when I add a label. 

Let's commit and push."

---

## Part 3: Automatic Scanning (2 minutes)

[Trigger workflow]

"Now let's run our first security scan.

RSOLV is analyzing my entire codebase, using advanced AST parsing to understand the actual flow of data through my application.

[Show running workflow]

This is key - RSOLV doesn't just pattern match. It understands your code's structure, which reduces false positives by 70-90%.

[Show completed scan]

Look at that - RSOLV found multiple critical vulnerabilities and automatically created detailed GitHub issues.

[Open issue list]

Let's look at one of these issues..."

---

## Part 4: Issue Details (1.5 minutes)

[Open SQL injection issue]

"Here's the SQL injection issue RSOLV created.

Notice how specific it is - exact file locations, line numbers, and code snippets. 

It explains the security impact in business terms - potential data breach, compliance violations, financial losses.

It even shows me exactly which lines are vulnerable and why.

But here's the amazing part - RSOLV doesn't just find problems. It can fix them too."

---

## Part 5: Automated Fix Generation (3 minutes)

[Add rsolv:automate label]

"By adding this label, I'm telling RSOLV to automatically fix these vulnerabilities.

[Show workflow running]

Behind the scenes, RSOLV is now:
- Using Claude's advanced AI to understand my codebase
- Analyzing the vulnerability in context
- Generating a comprehensive fix that follows security best practices
- Even writing tests to ensure the fix works

This isn't just find-and-replace. RSOLV understands my code patterns, frameworks, and architecture.

[Refresh page, show PR created]

And there it is - a complete pull request with the fix!"

---

## Part 6: Pull Request Review (2 minutes)

[Open pull request]

"Let's look at what RSOLV generated.

First, notice the comprehensive description. It explains what was vulnerable and why.

[Scroll to changes]

Here are the code changes. RSOLV replaced the vulnerable string concatenation with properly parameterized queries. This completely prevents SQL injection.

[Show test section]

It even added security tests to ensure the vulnerability doesn't come back.

[Show educational section]

And look at this - educational explanations at three levels:
- Executive summary with business impact
- Technical details for developers  
- Best practices for the future

This isn't just fixing code - it's teaching your team to write more secure code."

---

## Part 7: ROI and Benefits (1 minute)

[Show metrics/dashboard]

"Let's talk about impact.

What normally takes a security expert hours, RSOLV does in minutes.

With 90% fewer false positives, your team focuses on real vulnerabilities, not noise.

Every fix follows security best practices and includes tests.

And your team learns secure coding patterns with every PR.

For one customer, RSOLV reduced their security debt by 85% in just 3 months."

---

## Closing (30 seconds)

[Show RSOLV homepage]

"RSOLV transforms security from a bottleneck into an automated workflow.

Find vulnerabilities faster. Fix them automatically. Teach your team in the process.

Visit rsolv.dev to start your free trial and see how RSOLV can secure your code today.

Thanks for watching!"

---

## B-Roll Suggestions

1. **Code scrolling** showing various vulnerabilities
2. **GitHub Actions** running in real-time
3. **Dashboard metrics** showing scan results
4. **PR diff view** highlighting secure changes
5. **Terminal output** showing RSOLV in action

## Key Phrases to Emphasize

- "90% fewer false positives"
- "AI-powered fixes"
- "Teaches secure coding"
- "Minutes, not hours"
- "Follows best practices"
- "Includes tests"
- "Business impact"

## Technical Details to Mention

- AST (Abstract Syntax Tree) parsing
- Claude AI integration
- Test-driven development
- Parameterized queries
- Security best practices
- OWASP coverage

## Call-to-Action

- Visit rsolv.dev
- Start free trial
- See documentation
- Contact sales for enterprise

## Timing Summary

| Section | Duration |
|---------|----------|
| Opening | 30 seconds |
| The Problem | 45 seconds |
| Quick Setup | 1 minute |
| Automatic Scanning | 2 minutes |
| Issue Details | 1.5 minutes |
| Automated Fix | 3 minutes |
| PR Review | 2 minutes |
| ROI & Benefits | 1 minute |
| Closing | 30 seconds |
| **Total** | **~12 minutes** |