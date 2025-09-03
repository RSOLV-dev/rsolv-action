# RFC-025: Slopsquatting Detection & Prevention

**RFC Number**: 025  
**Title**: Slopsquatting Detection & Prevention System  
**Author**: RSOLV Security Team  
**Status**: Draft  
**Created**: June 19, 2025  
**Priority**: HIGH - Active Exploitation in Wild

## Summary

This RFC proposes implementing detection and prevention mechanisms for "slopsquatting" attacks - a new supply chain attack vector that exploits AI's tendency to hallucinate package names. Attackers pre-register these hallucinated packages with malicious code, creating a predictive supply chain attack that specifically targets AI-assisted development workflows.

## Motivation

### The Problem
Comprehensive research shows that:
- **19.6% of AI-generated code includes references to non-existent packages** (USENIX 2025 study across 16 coding models)
- **24.2% hallucination rate for GPT-4** with 19.6% repetition patterns (Lasso Security 2024)
- Attackers are actively registering these "phantom" packages
- Traditional security tools don't detect this attack vector
- The problem will grow as AI adoption increases

### Why RSOLV Should Address This
1. **First-mover advantage**: No security platform specifically detects slopsquatting
2. **Perfect AI security example**: Demonstrates our "AI-era security" positioning
3. **Real customer value**: Prevents actual supply chain attacks
4. **Technical differentiation**: Requires AI-aware detection logic

## Background

### What is Slopsquatting?
Coined by Seth Larson (Python core developer), slopsquatting is:
1. AI hallucinates a plausible package name (e.g., 'express-security-validator')
2. Attackers predict these hallucinations and pre-register the packages
3. Developers copy-paste AI suggestions and unknowingly install malware
4. Unlike typosquatting (human errors), this exploits AI behavior patterns

### Current Threat Landscape
- **Affected AI Models**: GPT-4, Claude, Copilot, Gemini
- **Affected Registries**: npm, PyPI, RubyGems, Packagist
- **Known Attacks**: Multiple confirmed cases as of June 2025
- **Risk Level**: HIGH - automated and scalable attack vector

## Proposed Solution

### 1. Detection Strategy

#### Pattern-Based Detection
```typescript
interface SlopsquattingPattern {
  id: string;
  name: string;
  description: string;
  detect: (packageName: string) => Promise<SlopsquattingRisk>;
  fix: (context: CodeContext) => Promise<Fix[]>;
}
```

#### Key Detection Patterns
1. **AI Naming Conventions**: Packages following AI's predictable patterns
2. **Phantom Dependencies**: Packages that shouldn't exist but do
3. **Timeline Analysis**: Packages created after AI training cutoffs
4. **Low Adoption Indicators**: Single version, minimal downloads
5. **Missing Metadata**: No repository, homepage, or documentation

### 2. Multi-Layer Validation

```typescript
class SlopsquattingValidator {
  async validate(dependency: Dependency): Promise<ValidationResult> {
    const checks = await Promise.all([
      this.checkExistence(dependency),
      this.checkCreationDate(dependency),
      this.checkNamingPatterns(dependency),
      this.checkAdoptionMetrics(dependency),
      this.checkSimilarPackages(dependency)
    ]);
    
    return {
      risk: this.calculateRiskScore(checks),
      evidence: this.compileEvidence(checks),
      recommendation: this.generateRecommendation(checks)
    };
  }
}
```

### 3. Real-Time Registry Monitoring

Monitor package registries for:
- Newly registered packages matching AI hallucination patterns
- Packages with names similar to common AI suggestions
- Suspicious registration patterns (bulk registrations)

### 4. Fix Generation

Automated remediation options:
1. **Replace with legitimate package**: Find the intended package
2. **Remove dependency**: If no legitimate alternative exists
3. **Add security comment**: Flag for manual review
4. **Create security policy**: Block package installation

## Implementation Plan

### Phase 1: Core Detection (Week 1)
- [ ] Implement AI naming pattern detection
- [ ] Build npm registry validation
- [ ] Create initial pattern library (10-15 patterns)
- [ ] Develop risk scoring algorithm

### Phase 2: Extended Coverage (Week 2)
- [ ] Add PyPI and RubyGems support
- [ ] Implement timeline-based detection
- [ ] Build similarity matching system
- [ ] Create fix generation logic

### Phase 3: Integration & Launch (Week 3)
- [ ] Integrate with existing RSOLV scanner
- [ ] Add UI indicators for slopsquatting risks
- [ ] Create demo scenarios
- [ ] Launch with announcement campaign

### Phase 4: Continuous Improvement (Ongoing)
- [ ] Monitor for new AI hallucination patterns
- [ ] Update detection algorithms
- [ ] Share threat intelligence
- [ ] Build community reporting system

## Technical Architecture

### Components
```
┌─────────────────────────────────────────────────┐
│           Slopsquatting Detection Engine         │
├─────────────────────────────────────────────────┤
│                                                 │
│  ┌──────────────┐  ┌──────────────┐           │
│  │   Pattern    │  │   Registry   │           │
│  │   Matcher    │  │  Validator   │           │
│  └──────┬───────┘  └──────┬───────┘           │
│         │                  │                    │
│         └────────┬─────────┘                   │
│                  │                              │
│          ┌───────▼────────┐                    │
│          │  Risk Analyzer  │                    │
│          └───────┬────────┘                    │
│                  │                              │
│          ┌───────▼────────┐                    │
│          │  Fix Generator │                    │
│          └────────────────┘                    │
└─────────────────────────────────────────────────┘
```

### Data Flow
1. Extract dependencies from code
2. Check each against slopsquatting patterns
3. Validate with package registry
4. Calculate risk score
5. Generate fixes if needed
6. Present results with evidence

## Success Metrics

### Technical Metrics
- Detection accuracy: >90%
- False positive rate: <5%
- Registry API response time: <500ms
- Pattern matching performance: <100ms per file

### Business Metrics
- Press coverage of slopsquatting detection
- Customer adoption of AI security features
- Prevented attacks (tracked and reported)
- Competitive differentiation established

### Market Validation
- 100+ scans using slopsquatting detection in week 1
- 20+ slopsquatting attempts detected
- 5+ customer testimonials
- 3+ security blog mentions

## Security Considerations

### Privacy
- Don't send package names to external services
- Hash package names for telemetry
- Allow customers to opt-out of detection

### Performance
- Cache registry lookups (1-hour TTL)
- Batch API requests
- Implement circuit breakers

### Accuracy
- Regular pattern updates
- Community-sourced intelligence
- Machine learning for pattern evolution

## Marketing & Positioning

### Key Messages
1. "First security platform to detect slopsquatting"
2. "Protect against AI-era supply chain attacks"
3. "Stop malware before it enters your codebase"

### Demo Scenarios
1. Scan AI-generated code
2. Detect hallucinated package
3. Show it was recently registered
4. Provide safe alternative
5. Generate automatic fix

### Content Opportunities
- Blog: "Discovering Slopsquatting in the Wild"
- Video: "How AI Hallucinations Become Security Threats"
- Report: "State of AI Supply Chain Security 2025"

## Alternatives Considered

### 1. Blocklist Approach
- Maintain list of known slopsquatting packages
- **Rejected**: Not scalable, reactive not proactive

### 2. AI Model Fine-tuning
- Train AI to not hallucinate packages
- **Rejected**: Outside our scope, doesn't help existing code

### 3. Manual Review Only
- Flag suspicious packages for human review
- **Rejected**: Doesn't scale, poor developer experience

## Future Extensions

### Near-term (3-6 months)
- Machine learning for pattern detection
- IDE plugin for real-time warnings
- Community threat intelligence sharing

### Long-term (6-12 months)
- Predictive slopsquatting prevention
- Registry partnership for blocking
- Industry standard for AI code security

## References

- ["We Have a Package for You! A Comprehensive Analysis of Package Hallucinations"](https://arxiv.org/html/2406.10279v3) - USENIX 2025 study confirming 19.6% average hallucination rate across 16 coding models
- ["AI Package Hallucinations"](https://www.lasso.security/blog/ai-package-hallucinations) - Lasso Security research showing 24.2% GPT-4 hallucination rate
- ["Slopsquatting: When AI Agents Hallucinate Malicious Packages"](https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/slopsquatting-when-ai-agents-hallucinate-malicious-packages) - Trend Micro analysis
- ["AI hallucinations lead to a new cyber threat: Slopsquatting"](https://www.csoonline.com/article/3961304/ai-hallucinations-lead-to-new-cyber-threat-slopsquatting.html) - CSO Online coverage
- ["AI-hallucinated code dependencies become new supply chain risk"](https://www.bleepingcomputer.com/news/security/ai-hallucinated-code-dependencies-become-new-supply-chain-risk/) - BleepingComputer technical analysis

## Decision

Implement slopsquatting detection as a high-priority feature that:
1. Provides immediate customer value
2. Establishes RSOLV as AI security leader
3. Demonstrates our technical innovation
4. Creates strong marketing differentiation

This aligns with our "AI-era security" positioning while solving a real, growing threat.