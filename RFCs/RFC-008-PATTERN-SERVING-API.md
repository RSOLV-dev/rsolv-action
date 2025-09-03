# RFC: Pattern Serving API

**RFC Number**: 008  
**Title**: Dynamic Security Pattern Serving API  
**Author**: RSOLV Team  
**Status**: Implemented  
**Created**: 2025-06-03  

## Summary

This RFC proposes moving security patterns from being hardcoded in RSOLV-action to being served dynamically from RSOLV-api. This would enable pattern updates without redeploying the action, centralized pattern management, and customer-specific pattern customization.

## Current State

Security patterns are currently hardcoded in RSOLV-action:
- `src/security/patterns/javascript-patterns.ts`
- `src/security/patterns/python-patterns.ts`
- `src/security/patterns/ruby-patterns.ts`
- `src/security/patterns/java-patterns.ts`

Total: ~76 patterns across 4 languages

## Motivation

1. **Update Velocity**: Currently requires RSOLV-action release to update patterns
2. **Customer Customization**: No way to add customer-specific patterns
3. **Pattern Evolution**: Can't A/B test or gradually roll out new patterns
4. **Maintenance**: Pattern updates coupled with action code changes
5. **Scalability**: As patterns grow, action size increases

## Proposed Solution

### Architecture

```mermaid
flowchart LR
    subgraph RSOLV-action
        PS[PatternSource Interface]
        LPS[LocalPatternSource]
        APS[ApiPatternSource]
        CACHE[Pattern Cache]
    end
    
    subgraph RSOLV-api
        PE[/api/v1/patterns]
        PDB[(Pattern DB)]
        VER[Version Manager]
    end
    
    PS --> LPS
    PS --> APS
    APS --> CACHE
    CACHE --> PE
    PE --> PDB
    PE --> VER
```

### Enhanced API Design for AI Security Strategy

#### Pattern Tiers for Market Strategy

| Tier | Access | Pattern Types | Customer Segment |
|------|--------|---------------|------------------|
| **Public** | No auth | Basic OWASP patterns | Free/Demo users |
| **Protected** | API key | Advanced framework patterns | Paying customers |
| **AI** | API key + feature flag | AI-specific patterns | AI security customers |
| **Enterprise** | Custom auth | Customer-specific patterns | Enterprise customers |

#### GET /api/v1/patterns/public/:language
Public patterns for trust-building and demos

```json
{
  "tier": "public",
  "language": "javascript", 
  "pattern_count": 25,
  "patterns": [
    {
      "id": "basic-sql-injection",
      "severity": "high",
      "pattern": "query\\s*\\+\\s*['\"]",
      "message": "Basic SQL injection vulnerability",
      "fix_pattern": "Use parameterized queries"
    }
  ]
}
```

#### GET /api/v1/patterns/protected/:language
Advanced patterns requiring authentication

```json
{
  "tier": "protected",
  "language": "javascript",
  "pattern_count": 150,
  "patterns": [
    {
      "id": "rails-mass-assignment",
      "severity": "high", 
      "pattern": "\\.update\\(params\\[",
      "message": "Rails mass assignment vulnerability",
      "fix_pattern": "Use strong parameters"
    }
  ]
}
```

#### GET /api/v1/patterns/ai/:language  
AI-specific patterns (competitive advantage)

```json
{
  "tier": "ai",
  "language": "javascript",
  "pattern_count": 30,
  "patterns": [
    {
      "id": "ai-hallucinated-package",
      "severity": "critical",
      "pattern": "require\\(['\"][@\\w-]+(?:-[\\w]+)*['\"]\\)",
      "validation": "npm_registry_check",
      "message": "AI suggested non-existent package",
      "fix_pattern": "Verify package exists before importing"
    },
    {
      "id": "ai-weak-crypto",
      "severity": "critical",
      "pattern": "crypto\\.createCipher\\(['\"](?:des|md5|rc4)",
      "message": "AI suggested deprecated cryptography",
      "fix_pattern": "Use crypto.createCipheriv with AES-256-GCM"
    }
  ]
}
```

### Enhanced RSOLV-action Integration (AI Security Strategy)

```typescript
interface PatternSource {
  getPatterns(language: string, tier?: PatternTier): Promise<SecurityPattern[]>;
}

enum PatternTier {
  PUBLIC = 'public',
  PROTECTED = 'protected', 
  AI = 'ai',
  ENTERPRISE = 'enterprise'
}

class TieredPatternSource implements PatternSource {
  constructor(
    private apiClient: RsolvApiClient,
    private cache: PatternCache,
    private fallback: LocalPatternSource,
    private customerTier: PatternTier
  ) {}
  
  async getPatterns(language: string, tier?: PatternTier): Promise<SecurityPattern[]> {
    const requestedTier = tier || this.customerTier;
    
    try {
      // Always include public patterns (for trust/demos)
      const publicPatterns = await this.fetchPublicPatterns(language);
      
      // Add protected patterns if customer has access
      if (this.hasAccess(requestedTier)) {
        const protectedPatterns = await this.fetchProtectedPatterns(language, requestedTier);
        return [...publicPatterns, ...protectedPatterns];
      }
      
      return publicPatterns;
    } catch (error) {
      // Graceful degradation to local basic patterns
      return this.fallback.getBasicPatterns(language);
    }
  }
  
  private async fetchPublicPatterns(language: string): Promise<SecurityPattern[]> {
    // Public patterns - no auth required
    return this.apiClient.get(`/api/v1/patterns/public/${language}`);
  }
  
  private async fetchProtectedPatterns(language: string, tier: PatternTier): Promise<SecurityPattern[]> {
    // Protected patterns - requires API key
    const cached = await this.cache.get(`${tier}-${language}`);
    if (cached && !cached.isExpired()) {
      return cached.patterns;
    }
    
    const patterns = await this.apiClient.get(`/api/v1/patterns/${tier}/${language}`, {
      headers: { 'Authorization': `Bearer ${this.apiKey}` }
    });
    
    await this.cache.set(`${tier}-${language}`, patterns, { ttl: 3600 });
    return patterns;
  }
  
  private hasAccess(tier: PatternTier): boolean {
    const tierHierarchy = [PatternTier.PUBLIC, PatternTier.PROTECTED, PatternTier.AI, PatternTier.ENTERPRISE];
    const customerLevel = tierHierarchy.indexOf(this.customerTier);
    const requestedLevel = tierHierarchy.indexOf(tier);
    return customerLevel >= requestedLevel;
  }
}

// AI Security Marketing Integration
class AISecurityAnalyzer {
  constructor(private patternSource: TieredPatternSource) {}
  
  async analyzeForAIVulnerabilities(code: string, language: string): Promise<AISecurityResult> {
    // Get AI-specific patterns (competitive advantage)
    const aiPatterns = await this.patternSource.getPatterns(language, PatternTier.AI);
    const protectedPatterns = await this.patternSource.getPatterns(language, PatternTier.PROTECTED);
    
    const vulnerabilities = [];
    
    // Check AI-specific vulnerabilities
    for (const pattern of aiPatterns) {
      const matches = this.analyzePattern(code, pattern);
      if (matches.length > 0) {
        vulnerabilities.push({
          type: 'ai-generated',
          pattern: pattern.id,
          severity: pattern.severity,
          description: pattern.message,
          fixSuggestion: pattern.fix_pattern,
          matches
        });
      }
    }
    
    return {
      aiVulnerabilityCount: vulnerabilities.filter(v => v.type === 'ai-generated').length,
      totalVulnerabilities: vulnerabilities.length,
      patternCoverage: aiPatterns.length + protectedPatterns.length,
      competitiveAdvantage: `Detected with ${aiPatterns.length} AI-specific patterns vs 0 in generic tools`,
      vulnerabilities
    };
  }
}
```

## Implementation Plan

### Phase 1: API Infrastructure (Week 1)
1. Create pattern storage schema in RSOLV-api
2. Build pattern serving endpoints
3. Implement version management
4. Add pattern validation

### Phase 2: Action Integration (Week 2)
1. Create PatternSource interface
2. Implement ApiPatternSource with caching
3. Keep LocalPatternSource as fallback
4. Add configuration for pattern source

### Phase 3: Migration (Week 3)
1. Import existing patterns to database
2. Test with select customers
3. Monitor performance impact
4. Document pattern management process

### Phase 4: Enhanced Features (Week 4+)
1. Customer-specific patterns
2. Pattern effectiveness tracking
3. A/B testing framework
4. Pattern contribution workflow

## Alternatives Considered

1. **Git Submodules**: Patterns in separate repo
   - ❌ Still requires action updates
   - ❌ Complex dependency management

2. **NPM Package**: Patterns as separate package
   - ❌ Still coupled to release cycle
   - ❌ No runtime updates

3. **S3/CDN**: Static pattern files
   - ❌ No API features (search, filter)
   - ❌ Limited access control

## Performance Considerations

- Cache patterns for 1 hour (configurable)
- Bundle patterns by language, not individually
- Use ETags for efficient cache validation
- Compress pattern payloads
- Fall back to local patterns on API failure

## Security Considerations

- Patterns are read-only from action perspective
- API authentication via existing RSOLV API keys
- Rate limiting to prevent abuse
- Audit trail for pattern changes
- No customer data in patterns

## Open Questions

1. Should we version patterns independently or as a set?
2. How to handle breaking pattern changes?
3. Should customers be able to disable specific patterns?
4. What metrics should we track for pattern effectiveness?

## Success Metrics

- Pattern update time: < 5 minutes (vs current release cycle)
- API response time: < 100ms for pattern fetch
- Cache hit rate: > 95%
- Zero increase in action failure rate

## References

- Current pattern implementation: `RSOLV-action/src/security/patterns/`
- Credential vending RFC: `RSOLV-docs/architecture/credential-vending-service.md`
- Security patterns PR: #127 (hypothetical)

## Decision

**Status**: ✅ APPROVED & IN PROGRESS - Implementation Started (June 7, 2025)

**Strategic Context Changed**: Originally deferred, now MISSION CRITICAL due to:
1. ✅ Billing infrastructure is complete (RFC-004 implemented)
2. ✅ AI-first market strategy requires IP protection before public campaign
3. ✅ About to launch aggressive marketing that will expose all patterns
4. ✅ Credential vending system ready (RFC-012 implemented)

**New Priority**: Must implement before any public marketing activities (FITZ-196, FITZ-195, FITZ-198).

## Updated Implementation Plan for AI Security Strategy

### Pre-Launch Critical (Days 1-5) 🚨

**MUST COMPLETE BEFORE CAMPAIGN LAUNCH**

**Day 1**: Repository Cleanup & History Protection 🚨 CRITICAL

**Git History Sanitization** (IRREVERSIBLE - Plan Carefully):
- [ ] **Backup Current State**: Full repository backup before history rewriting
- [ ] **Identify Pattern Commits**: `git log --oneline --grep="pattern" src/security/patterns/`
- [ ] **History Rewrite**: Use `git filter-repo` to remove all pattern files from history
  ```bash
  # Remove pattern directories from entire Git history
  git filter-repo --path src/security/patterns --invert-paths
  git filter-repo --path-regex '.*pattern.*\.ts' --invert-paths
  ```
- [ ] **Force Push**: `git push --force-with-lease` (IRREVERSIBLE)
- [ ] **Verify Clean History**: Ensure no pattern content in any commit

**GitHub Action Marketplace Cleanup**:
- [ ] **Identify Published Versions**: List all versions containing patterns
- [ ] **Deprecate Old Versions**: Mark v1.0-v1.4 as deprecated with "Security update required"
- [ ] **Unpublish if Possible**: Remove from marketplace if GitHub allows
- [ ] **Update Documentation**: Clear migration path to new API-based version

**Branch Protection**:
- [ ] **Scan All Branches**: `git branch -a | xargs git grep -l "SecurityPattern"`
- [ ] **Clean Development Branches**: Remove patterns from feature branches
- [ ] **Update .gitignore**: Prevent accidental re-addition of pattern files

**Day 2-3**: API Implementation (Enhanced for AI Strategy)
- [ ] **Protected Pattern Storage**: Database schema for tiered pattern access
- [ ] **AI-Specific Endpoints**: Dedicated endpoints for AI vulnerability patterns  
- [ ] **Customer Segmentation**: Basic/Pro/Enterprise pattern tiers

**Day 4-5**: Action Integration & Deployment
- [ ] **Hybrid Pattern Source**: Call API for advanced patterns, local for basic
- [ ] **Graceful Degradation**: Fallback to basic patterns if API unavailable
- [ ] **Production Deployment**: Full pipeline with IP protection

### Phase 2: Enhanced Features (Week 2-4)
- Customer-specific patterns
- Pattern effectiveness tracking  
- A/B testing framework
- Advanced AI pattern development

## Marketing Integration Strategy

### Public Trust Building
- **Public Patterns**: Keep ~25 basic OWASP patterns public for demos and trust
- **Transparency**: Show capability without revealing competitive advantage
- **Demo-Friendly**: Public patterns sufficient for convincing demonstrations

### Competitive Differentiation
- **AI-Specific Messaging**: "First platform with AI vulnerability detection"
- **Pattern Count Claims**: "448 comprehensive patterns vs competitors' 40-80"
- **Zero Competition**: "Only platform detecting AI hallucination vulnerabilities"

### Customer Value Ladder
1. **Free Trial**: Public patterns demonstrate basic capability
2. **Paid Tiers**: Advanced patterns justify premium pricing  
3. **AI Security**: Unique AI patterns command market premium
4. **Enterprise**: Custom patterns create switching costs

### Campaign Messaging (Enabled by Pattern Protection)
- ✅ "Proprietary AI security engine" 
- ✅ "Zero competition in AI vulnerability detection"
- ✅ "10x more patterns than generic tools"
- ✅ "First and only AI security platform"

## Risk Mitigation

### IP Protection Success Metrics
- [ ] **Zero Pattern Exposure**: No proprietary patterns in public repositories
- [ ] **Clean Git History**: No pattern content accessible via Git history
- [ ] **Marketplace Cleanup**: Old action versions deprecated/removed
- [ ] **Graceful Degradation**: Action works with public patterns if API fails
- [ ] **Performance Maintained**: <100ms additional latency for pattern fetching

### Competitive Monitoring
- [ ] **Repository Monitoring**: Watch for competitors examining our code
- [ ] **Pattern Copying Detection**: Monitor for our pattern signatures in competitor tools
- [ ] **Market Response Tracking**: Track competitor reactions to our AI security claims
- [ ] **Legal Protection**: Consider pattern IP protection mechanisms