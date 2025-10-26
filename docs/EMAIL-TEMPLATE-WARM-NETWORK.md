# Email Template: Warm Network Launch Announcement

**Audience**: Personal contacts, former colleagues, fellow founders
**Timing**: Launch day (Hour 0-4)
**Goal**: Early adopters, word-of-mouth, feedback

---

## Subject Lines (A/B Test)

**Option A (Direct)**:
```
RSOLV is live: AI security for GitHub Actions
```

**Option B (Personal)**:
```
I built an AI security engineer (would love your feedback)
```

**Option C (Problem-focused)**:
```
Tired of false positive security alerts?
```

---

## Email Body

**Version 1: Warm Network (Use for personal contacts)**

```
Hi [First Name],

Quick update: I just launched RSOLV on GitHub Marketplace.

**What it is**: An AI security engineer that validates vulnerabilities with executable tests before fixing them.

**Why it matters**: Security scanners have a false positive problem. RSOLV guarantees every finding is real—if it can't write a failing test proving the vulnerability, it doesn't report it.

**How it works**:
1. SCAN: Detect vulnerabilities (SQL injection, XSS, etc.)
2. VALIDATE: Generate RED test proving it exists
3. MITIGATE: Create PR with fix that makes test GREEN

It's live now: [GitHub Marketplace link]

**I'd love your help:**
- Try it (10 free credits, no CC required)
- Share feedback (brutal honesty welcome)
- Forward to anyone who might find this useful

If you're building something with a security component, I'd be happy to jump on a call and discuss how RSOLV could help.

Thanks,
Dylan

P.S. Here's a 3-minute walkthrough: [screencast link]
```

---

**Version 2: Professional Network (Use for LinkedIn contacts, former colleagues)**

```
Subject: Launching RSOLV: Test-First AI Security for GitHub Actions

Hi [First Name],

I'm excited to share that RSOLV is now live on GitHub Marketplace.

**The problem**: Security scanners have a 60-80% false positive rate. Teams waste hours reviewing non-existent issues, leading to alert fatigue and ignored findings.

**Our approach**: RSOLV is the first AI security tool that proves vulnerabilities before reporting them. It generates executable RED tests demonstrating real exploit scenarios, then creates fixes that make tests GREEN.

**Key benefits**:
- Zero false positives (no test = no report)
- Educational: Every PR includes security context
- Multi-language: JS, TS, Python, Ruby, Go, Java
- OWASP Top 10 coverage

**Quick stats**:
- 170+ security patterns
- AST-validated detection
- 3-step installation (< 5 minutes)

**Try it**: [Marketplace link]
- 10 free trial credits
- No credit card required
- Full documentation at docs.rsolv.dev

I'd appreciate any feedback from your team's experience. If RSOLV could help with your security workflows, I'm happy to schedule a demo.

Best,
Dylan

---
Dylan Nguyen
Founder, RSOLV
dylan@arborealstudios.com
https://rsolv.dev
```

---

**Version 3: Developer Community (Use for GitHub connections, OSS contributors)**

```
Subject: Show HN: RSOLV - AI that validates vulnerabilities before fixing them

Hey [First Name],

Launching RSOLV today on GitHub Marketplace. Thought you might find it interesting given your work on [their project/expertise].

**TLDR**: AI security engineer that writes failing tests to prove vulnerabilities exist before proposing fixes.

**Why this matters**:
- Traditional scanners: "This might be vulnerable 🤷"
- RSOLV: "Here's a test proving it's exploitable ✅"

**Example workflow**:
```yaml
- uses: RSOLV-dev/RSOLV-action@v1
  with:
    rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
    mode: scan  # or validate, mitigate
```

**Modes**:
- `scan`: Read-only detection
- `validate`: Scan + RED test generation
- `mitigate`: Full automation (scan → test → PR)

**Free tier**: 10 credits to try it out
**Docs**: docs.rsolv.dev
**Install**: [Marketplace link]

Would love your feedback—especially on false positives/negatives if you try it.

Cheers,
Dylan

P.S. Open to pattern contributions if you're interested in expanding coverage.
```

---

## Follow-Up Sequences

### Day 3: Non-Responders
```
Subject: Re: RSOLV launch

[First Name],

Following up on my last email about RSOLV.

No pressure at all—just wanted to share one more thing:

**Most common feedback so far**: "I didn't realize how many false positives my current scanner produces until RSOLV showed me what's actually exploitable."

If you're curious, here's a 90-second demo: [video link]

Thanks,
Dylan
```

### Day 7: Trial Users (Feedback Request)
```
Subject: How's RSOLV working for you?

Hi [First Name],

Saw you installed RSOLV—thanks for trying it!

Quick question: What's working? What's not?

I'm collecting feedback for the next release and would love to hear your experience:
- False positives/negatives?
- Installation friction?
- Feature requests?

Reply directly or book 15 min: [calendar link]

Appreciate your time,
Dylan
```

### Day 14: Trial Expiring (Conversion)
```
Subject: Your RSOLV trial credits

Hi [First Name],

You've used [X]/10 trial credits. Nice!

**Quick summary of what RSOLV found**:
- [Y] vulnerabilities detected
- [Z] validated with RED tests
- [N] fixed via automated PRs

**Next steps**:

If RSOLV is working for you, consider upgrading:
- Pay-as-you-go: $29/month + usage
- Pro: $599/month (500 credits)

If you're on the fence, I'm happy to extend your trial. Just reply.

Thanks,
Dylan

P.S. If you're not finding value, I'd love to know why. Feedback helps us improve.
```

---

## Tracking & Optimization

### Email Metrics to Monitor
- **Open rate** (target: >30% for warm network)
- **Click-through rate** (target: >10%)
- **Reply rate** (target: >5%)
- **Install rate** (target: >3%)

### A/B Tests
- Subject line variations (personal vs. professional)
- Email length (short vs. detailed)
- CTA placement (top vs. bottom)
- Social proof (testimonials vs. stats)

### Segmentation
- **Tier 1**: Close contacts, former colleagues (Version 1)
- **Tier 2**: Professional network, LinkedIn (Version 2)
- **Tier 3**: Developer community, GitHub (Version 3)

---

## Opt-Out & Privacy

Include in footer:
```
---
You're receiving this because we've worked together or connected professionally.
If you'd prefer not to receive updates about RSOLV, reply with "unsubscribe."

RSOLV, LLC
support@rsolv.dev
https://rsolv.dev/privacy
```

---

## Next Steps Post-Send

1. **Monitor replies** within 1 hour
2. **Personal responses** for all questions/feedback
3. **Book demos** for interested leads
4. **Tag contacts** in CRM (interested/not-interested/trial-user)
5. **Follow up** day 3, 7, 14 based on engagement

---

**Reference**: RFC-067 lines 588, 605
**Launch Plan**: LAUNCH-PLAN.md
