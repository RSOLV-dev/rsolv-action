# UTM Tracking & Launch Coordination Plan

**Purpose**: Comprehensive tracking and coordination for Week 6 marketing launch
**Created**: 2025-11-04
**Owner**: Dylan Nguyen
**Launch Date**: TBD (upon GitHub Marketplace approval)

---

## UTM Parameter Strategy

### Parameter Structure
All URLs follow this format:
```
https://rsolv.dev?utm_source={source}&utm_medium={medium}&utm_campaign={campaign}&utm_content={content}
```

### Parameter Definitions

**utm_source** - Where traffic originates:
- `mastodon` - Mastodon posts (@rsolv@infosec.exchange)
- `linkedin` - LinkedIn posts/articles
- `indiehackers` - IndieHackers community
- `twitter` - Twitter/X posts (if applicable)
- `bluesky` - Bluesky posts
- `devto` - Dev.to articles
- `medium` - Medium articles
- `github` - GitHub README, discussions
- `email` - Email campaigns (future)
- `direct` - Direct traffic (no UTM)

**utm_medium** - Type of marketing:
- `social` - Social media posts
- `article` - Long-form content
- `profile` - Profile link bio
- `comment` - Comment/reply engagement
- `community` - Community discussion posts
- `email` - Email campaigns

**utm_campaign** - Specific campaign:
- `launch` - Initial product launch
- `week1_results` - Week 1 traction update
- `customer_interviews` - Customer insight sharing
- `5k_milestone` - Revenue milestone posts
- `feature_announcement` - New feature releases
- `thought_leadership` - Educational/technical content

**utm_content** - Specific content piece:
- `main_post` - Primary launch announcement
- `thread` - Threaded social media content
- `followup` - Follow-up posts
- `technical_deep_dive` - Technical explanation content
- `use_cases` - Use case/persona content
- `docs` - Link to documentation
- `pricing` - Link to pricing page

---

## Complete UTM Link Reference

### Mastodon (@rsolv@infosec.exchange)

**Main Launch Thread (Post 1/10):**
```
https://rsolv.dev?utm_source=mastodon&utm_medium=social&utm_campaign=launch&utm_content=thread
https://github.com/marketplace/actions/rsolv?utm_source=mastodon&utm_medium=social&utm_campaign=launch&utm_content=thread
```

**Technical Deep Dive Post:**
```
https://rsolv.dev?utm_source=mastodon&utm_medium=social&utm_campaign=launch&utm_content=technical_deep_dive
https://docs.rsolv.dev?utm_source=mastodon&utm_medium=social&utm_campaign=launch&utm_content=technical_deep_dive
```

**Profile Link (Bio):**
```
https://rsolv.dev?utm_source=mastodon&utm_medium=profile&utm_campaign=launch
```

**Follow-Up Posts (Day 2, 4, 7):**
```
Day 2:
https://rsolv.dev?utm_source=mastodon&utm_medium=social&utm_campaign=launch&utm_content=day2_followup

Day 4:
https://rsolv.dev?utm_source=mastodon&utm_medium=social&utm_campaign=launch&utm_content=day4_followup

Day 7 (Week 1 Results):
https://rsolv.dev?utm_source=mastodon&utm_medium=social&utm_campaign=week1_results&utm_content=traction
```

---

### LinkedIn

**Main Launch Post:**
```
https://rsolv.dev?utm_source=linkedin&utm_medium=social&utm_campaign=launch&utm_content=main_post
https://github.com/marketplace/actions/rsolv?utm_source=linkedin&utm_medium=social&utm_campaign=launch&utm_content=main_post
```

**Technical Deep Dive Post (Day 2):**
```
https://rsolv.dev?utm_source=linkedin&utm_medium=social&utm_campaign=launch&utm_content=technical_deep_dive
```

**Use Cases Post (Day 5):**
```
https://rsolv.dev?utm_source=linkedin&utm_medium=social&utm_campaign=launch&utm_content=use_cases
```

**Week 1 Results Post:**
```
https://rsolv.dev?utm_source=linkedin&utm_medium=social&utm_campaign=week1_results&utm_content=traction
```

**LinkedIn Article (Long-Form):**
```
https://rsolv.dev?utm_source=linkedin&utm_medium=article&utm_campaign=launch&utm_content=thought_leadership
https://docs.rsolv.dev?utm_source=linkedin&utm_medium=article&utm_campaign=launch&utm_content=thought_leadership
```

**LinkedIn Profile Link:**
```
https://rsolv.dev?utm_source=linkedin&utm_medium=profile&utm_campaign=launch
```

---

### IndieHackers

**Main Launch Post:**
```
https://rsolv.dev?utm_source=indiehackers&utm_medium=launch&utm_campaign=launch_post&utm_content=main
https://docs.rsolv.dev?utm_source=indiehackers&utm_medium=launch&utm_campaign=launch_post&utm_content=docs
https://rsolv.dev/pricing?utm_source=indiehackers&utm_medium=launch&utm_campaign=launch_post&utm_content=pricing
```

**Week 1 Revenue Post:**
```
https://rsolv.dev?utm_source=indiehackers&utm_medium=community&utm_campaign=week1_revenue&utm_content=metrics
```

**Customer Interview Insights Post:**
```
https://rsolv.dev?utm_source=indiehackers&utm_medium=community&utm_campaign=customer_interviews&utm_content=insights
```

**$5K MRR Milestone Post:**
```
https://rsolv.dev?utm_source=indiehackers&utm_medium=community&utm_campaign=5k_milestone&utm_content=breakdown
```

**Profile Link:**
```
https://rsolv.dev?utm_source=indiehackers&utm_medium=profile&utm_campaign=ongoing
```

---

### Blog Post (rsolv.dev/blog)

**Internal Cross-Links (within blog post):**
```
https://rsolv.dev?utm_source=blog&utm_medium=article&utm_campaign=launch&utm_content=cta
https://docs.rsolv.dev?utm_source=blog&utm_medium=article&utm_campaign=launch&utm_content=docs_link
https://github.com/marketplace/actions/rsolv?utm_source=blog&utm_medium=article&utm_campaign=launch&utm_content=marketplace
```

**Social Share Buttons:**
```
Mastodon:
https://rsolv.dev/blog/rsolv-launch-test-first-ai-security?utm_source=mastodon&utm_medium=social&utm_campaign=blog_share&utm_content=launch_post

LinkedIn:
https://rsolv.dev/blog/rsolv-launch-test-first-ai-security?utm_source=linkedin&utm_medium=social&utm_campaign=blog_share&utm_content=launch_post

Twitter:
https://rsolv.dev/blog/rsolv-launch-test-first-ai-security?utm_source=twitter&utm_medium=social&utm_campaign=blog_share&utm_content=launch_post
```

---

### Dev.to (Cross-Posted Blog)

**Dev.to Article Links:**
```
https://rsolv.dev?utm_source=devto&utm_medium=article&utm_campaign=launch&utm_content=cross_post
https://github.com/marketplace/actions/rsolv?utm_source=devto&utm_medium=article&utm_campaign=launch&utm_content=marketplace
```

**Canonical URL** (if cross-posting):
```
https://rsolv.dev/blog/rsolv-launch-test-first-ai-security
```

---

### GitHub

**RSOLV-action README:**
```
https://rsolv.dev?utm_source=github&utm_medium=readme&utm_campaign=ongoing&utm_content=action_readme
https://docs.rsolv.dev?utm_source=github&utm_medium=readme&utm_campaign=ongoing&utm_content=action_readme
```

**GitHub Discussions:**
```
https://rsolv.dev?utm_source=github&utm_medium=community&utm_campaign=discussions&utm_content=announcement
```

**Marketplace Listing:**
(No UTM needed - GitHub tracks this natively)

---

## Launch Timing Coordination

### Launch Day Timeline (Tuesday, 10am PT)

**Pre-Launch (9:00am PT)**
- [ ] Final review of all content (typos, links, UTM parameters)
- [ ] Verify GitHub Marketplace listing is live
- [ ] Verify rsolv.dev pricing page is accurate
- [ ] Test signup flow end-to-end
- [ ] Alert monitoring (Grafana dashboards open)
- [ ] Team notification: "Launch in 1 hour"

**10:00am PT - Main Launch**
- [ ] **Mastodon**: Post thread (1/10), schedule remaining 9 posts (10-minute intervals)
- [ ] **LinkedIn**: Post main announcement (Version A or B)
- [ ] **Blog**: Publish launch blog post, verify canonical URLs

**12:00pm PT - Extended Launch**
- [ ] **IndieHackers**: Post launch story with metrics
- [ ] **Dev.to**: Cross-post blog article (with canonical URL)
- [ ] **Bluesky**: Post short launch announcement

**2:00pm PT - Community Engagement**
- [ ] **GitHub Discussions**: Post announcement thread
- [ ] **Twitter/X**: Post launch tweet (if applicable)
- [ ] Update RSOLV-action README with launch notes

**4:00pm PT - First Check-In**
- [ ] Review engagement metrics across all channels
- [ ] Respond to all comments/questions (target < 2 hour response time)
- [ ] Check analytics: UTM-tracked traffic, trial signups
- [ ] Adjust follow-up messaging based on early feedback

**End of Day (6:00pm PT)**
- [ ] Summarize Day 1 metrics (internal doc)
- [ ] Plan Day 2 engagement strategy
- [ ] Schedule response to overnight comments (morning)

---

## Post-Launch Cadence

### Daily (Days 1-7)
- **9am PT**: Review overnight comments/questions, respond to all
- **12pm PT**: Check analytics dashboard (traffic, signups, conversions)
- **3pm PT**: Engage with new comments, answer questions
- **6pm PT**: Daily metrics summary (internal tracking)

### Weekly (Weeks 2-4)
- **Monday 9am PT**: Weekly metrics review, plan content for week
- **Tuesday 10am PT**: Follow-up post (Mastodon/LinkedIn rotation)
- **Thursday 2pm PT**: Community engagement (IndieHackers, GitHub Discussions)
- **Friday 5pm PT**: Weekly summary, document learnings

### Monthly (Months 2-3)
- **First Tuesday of month**: Milestone post (revenue, traction)
- **Mid-month**: Product update or feature announcement
- **End of month**: Month-in-review, metrics transparency

---

## Analytics Tracking Setup

### Google Analytics 4 Setup

**Event Tracking**:
```javascript
// Trial signup event
gtag('event', 'trial_signup', {
  'source': utm_source,
  'medium': utm_medium,
  'campaign': utm_campaign,
  'content': utm_content
});

// Marketplace click event
gtag('event', 'marketplace_click', {
  'source': utm_source,
  'medium': utm_medium,
  'campaign': utm_campaign
});

// Docs view event
gtag('event', 'docs_view', {
  'source': utm_source,
  'page': docs_page_path
});
```

**Custom Dimensions**:
- `utm_source` → Traffic Source
- `utm_medium` → Traffic Medium
- `utm_campaign` → Campaign Name
- `utm_content` → Content Identifier

**Goals**:
1. Trial signup (conversion)
2. Pricing page view (micro-conversion)
3. Docs engagement (engagement)
4. Marketplace listing view (awareness)

---

### Dashboard Tracking (Grafana/Custom)

**Launch Metrics Dashboard**:
- **Real-time traffic** by UTM source
- **Trial signups** by channel (last 24h, 7d, 30d)
- **Conversion funnel**: Homepage → Pricing → Signup
- **Top UTM campaigns** by signup volume
- **Channel ROI**: Signups per post/effort

**Key Metrics to Track**:
| Metric | Target (Day 1) | Target (Week 1) | Target (Month 1) |
|--------|---------------|----------------|-----------------|
| **Website visits** | 500+ | 2,000+ | 10,000+ |
| **Trial signups** | 5-10 | 25-50 | 100-150 |
| **Paying conversions** | 1-2 | 5-10 | 15-25 |
| **MRR** | $29-$598 | $145-$2,995 | $435-$8,985 |

**Attribution Windows**:
- **First-touch attribution**: Credit to initial UTM source
- **Last-touch attribution**: Credit to final UTM source before conversion
- **Multi-touch attribution**: Weighted credit across customer journey

---

## Channel-Specific Success Metrics

### Mastodon (@rsolv@infosec.exchange)
**Engagement Targets**:
- Boosts: 50+ (main thread)
- Favorites: 100+ (main thread)
- Replies: 20+ meaningful discussions
- Profile visits: 200+
- Click-through rate: 5-10% to rsolv.dev

**Attribution**:
- Trial signups: 10-20 (target)
- Paying conversions: 2-5 (target)
- Community building: High engagement with InfoSec community

---

### LinkedIn
**Engagement Targets**:
- Impressions: 1,000+ (main post)
- Reactions: 50+ (main post)
- Comments: 10+ meaningful discussions
- Shares: 5-10
- Profile visits: 100+

**Attribution**:
- Trial signups: 15-25 (target)
- Paying conversions: 3-8 (target)
- B2B lead generation: Inbound DMs from CTOs/VPs

---

### IndieHackers
**Engagement Targets**:
- Upvotes: 50+ (launch post)
- Comments: 20+ discussions
- Profile followers: +50
- Click-through: 100+ visits

**Attribution**:
- Trial signups: 5-15 (target)
- Paying conversions: 1-3 (target)
- Community credibility: High "building in public" reputation

---

### Blog (rsolv.dev/blog)
**Engagement Targets**:
- Page views: 500+ (Day 1), 2,000+ (Week 1)
- Avg. time on page: 5+ minutes (indicates reading)
- Bounce rate: < 60%
- Social shares: 20+

**Attribution**:
- Trial signups: 10-20 (target)
- Paying conversions: 2-5 (target)
- SEO value: Organic traffic over time (long-tail)

---

## A/B Testing Plan

### Week 1: Main Post Variations

**Test A vs. B on LinkedIn**:
- **Version A**: Problem-solution focus ("False positive fatigue...")
- **Version B**: Founder journey focus ("Six months ago...")
- **Metric**: Engagement rate, click-through to rsolv.dev
- **Decision point**: Day 3 (72 hours of data)

**Test on Mastodon**:
- **Variation 1**: Technical thread (current plan)
- **Variation 2**: Story-driven thread (alternative)
- **Metric**: Boosts + favorites + replies combined
- **Decision point**: Day 2 (48 hours of data)

---

### Week 2-4: CTA Variations

**Test on blog post CTAs**:
- **CTA A**: "Try RSOLV Today" (direct)
- **CTA B**: "Start Your Free Trial" (benefit-focused)
- **CTA C**: "See RSOLV in Action" (demo-focused)
- **Metric**: Click-through rate to signup
- **Decision point**: Week 2 (100+ clicks per variation)

---

## Reporting Cadence

### Daily Reports (Days 1-7)
**Send to**: Internal team/founder
**Format**: Slack/email summary
**Contents**:
- Total website visits (by UTM source)
- Trial signups (by channel)
- Paying conversions (by channel)
- Top 3 performing posts/channels
- Issues/concerns/anomalies

---

### Weekly Reports (Weeks 2-4)
**Send to**: Internal team + advisors
**Format**: Google Doc + Grafana dashboard
**Contents**:
- Week-over-week growth metrics
- Channel performance comparison
- Conversion funnel analysis
- Customer feedback themes
- Action items for next week

---

### Monthly Reports (Month 1+)
**Send to**: Internal team + advisors + investors (if applicable)
**Format**: Comprehensive deck or doc
**Contents**:
- MRR growth and customer acquisition
- Channel ROI analysis
- Customer cohort analysis
- Churn/retention metrics
- Product roadmap updates
- Key learnings and pivots

---

## Pre-Launch Checklist

### Content Readiness
- [ ] Mastodon thread: 10 posts drafted, UTM links added
- [ ] LinkedIn post: Version A and B ready, UTM links added
- [ ] IndieHackers post: Metrics placeholders ready for real data
- [ ] Blog post: Published with canonical URL, UTM links in CTAs
- [ ] Dev.to cross-post: Drafted with canonical URL back to blog

### UTM Setup
- [ ] All UTM links documented in this file
- [ ] UTM parameters tested (click-through verification)
- [ ] Google Analytics configured to capture UTM parameters
- [ ] Custom dashboard created for launch metrics
- [ ] Conversion goals set up in analytics

### Timing Coordination
- [ ] Launch day timeline reviewed (10am PT start)
- [ ] Calendar reminders set for each post time
- [ ] Team notified of launch schedule
- [ ] Response templates prepared for common questions
- [ ] Monitoring dashboards open and ready

### Technical Readiness
- [ ] rsolv.dev homepage loads correctly
- [ ] Signup flow tested end-to-end
- [ ] Pricing page accurate and up-to-date
- [ ] GitHub Marketplace listing live and accurate
- [ ] API endpoints healthy (< 1% error rate verified)
- [ ] Monitoring alerts configured (Prometheus/Grafana)

### Contingency Planning
- [ ] Rollback plan if critical issues found post-launch
- [ ] Support email monitored (support@rsolv.dev)
- [ ] Escalation path for technical issues
- [ ] Founder available for first 48 hours (high engagement)

---

## Post-Launch Review (1 Week After)

### Review Questions
1. **Which channel drove the most trial signups?**
2. **What was the conversion rate from each channel?**
3. **Which messaging resonated best? (problem-solution vs. journey)**
4. **What questions came up repeatedly? (update FAQ/docs)**
5. **What technical issues occurred? (root cause analysis)**
6. **What would we do differently next time?**

### Optimization Actions
- Update low-performing content based on engagement data
- Double down on high-performing channels
- Adjust UTM tracking if needed (add new parameters)
- Refine messaging based on customer feedback
- Document learnings for future product launches

---

**Document Owner**: Dylan Nguyen
**Last Updated**: 2025-11-04
**Status**: Ready for launch execution
**Next Review**: 1 week post-launch (Week 2)
