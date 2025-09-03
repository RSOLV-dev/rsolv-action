# ADR-015: Pattern Tier Removal

## Status
Accepted - Implemented

## Context

RSOLV originally implemented a tier-based pattern access system with four tiers:
- Public: 10 patterns (free access)
- Protected: ~40 patterns (basic paid tier)
- AI: 133 patterns (AI-enhanced tier)
- Enterprise: 27 patterns (enterprise tier)

This created several problems:
1. **Complex pricing model**: Multiple tiers confused customers
2. **Technical complexity**: 4x memory usage storing same patterns multiple times
3. **Artificial restrictions**: Patterns were artificially limited by tier
4. **Customer confusion**: Unclear which tier provided which patterns
5. **Development overhead**: Complex access control logic throughout codebase

## Decision

We will remove the tier-based system and implement a simplified binary access model:

### New Access Model
- **Demo Access**: 5 curated patterns per language (no API key required)
- **Full Access**: All 170 patterns across all languages (valid API key required)

### Technical Changes
1. Remove all tier-based routes and controller actions
2. Simplify PatternServer to store patterns once per language (not 4x per tier)
3. Update API to use authentication-based access control
4. Maintain backward compatibility for existing API calls
5. Provide clear migration path for existing customers

## Consequences

### Positive
- **Simplified pricing**: Binary model easier to understand and sell
- **Reduced memory usage**: 75% reduction in pattern storage memory
- **Clearer value proposition**: Demo vs full access is intuitive
- **Faster development**: Less complex access control logic
- **Better performance**: Fewer ETS lookups and reduced memory pressure
- **Easier testing**: Simpler access paths to validate

### Negative
- **Migration effort**: Existing tier-based integrations need updates
- **Documentation updates**: All tier references need removal
- **Customer communication**: Need to notify existing customers of changes

### Neutral
- **Same functionality**: All patterns remain available with API key
- **Same security**: Access control maintained through authentication
- **Backward compatibility**: Existing API calls continue to work

## Implementation

### Phase 1: Router and Controller Cleanup ✅
- Remove tier-based routes (`/public`, `/protected`, `/ai`, `/enterprise`)
- Keep main endpoint `/api/v1/patterns/` with access-based logic
- Add `/api/v1/patterns/stats` for transparency
- Simplify V2 API to default to enhanced format

### Phase 2: PatternServer Optimization ✅
- Remove tier-based storage (4x → 1x per language)
- Simplify `get_patterns(language)` interface
- Maintain backward compatibility for existing calls
- Reduce memory footprint by ~75%

### Phase 3: Compatibility Validation ✅
- Verify RSOLV-action continues working
- Test all API endpoints
- Validate customer journey end-to-end
- Confirm 170 patterns loading correctly

### Phase 4: Documentation and Communication
- Update API documentation
- Create customer migration guide
- Update pricing pages
- Notify existing customers

## Monitoring

### Success Metrics
- API response times remain < 200ms
- Memory usage reduced by 60-80%
- RSOLV-action compatibility maintained
- Customer onboarding improved (simpler model)
- Zero customer churn from tier removal

### Rollback Plan
If issues arise:
1. Revert router changes to restore tier endpoints
2. Restore tier-based storage in PatternServer
3. Update controllers to use tier logic
4. Communicate rollback to customers

## Alternatives Considered

### Option 1: Keep tiers, simplify pricing
- **Rejected**: Still complex technically and for customers
- Technical debt would remain

### Option 2: Grandfather existing tiers
- **Rejected**: Creates two different systems to maintain
- Increases complexity instead of reducing it

### Option 3: Usage-based pricing instead of tiers
- **Considered**: Could implement later on top of binary access
- Current binary model enables future usage-based pricing

## References

- [RFC-032: Enhanced Pattern Support](../RFCs/RFC-032-PATTERN-API-JSON-MIGRATION.md)
- [Pricing Strategy Discussion](../archived/day-8-9-docs/revised-pricing-structure.md)
- [Customer Journey Testing](./test-full-customer-journey.sh)
- [Pattern Count Validation](./RFC-032-PHASE-1-3-RESULTS.md)

## Decision Date
2025-06-30

## Decision Makers
- Dylan (Engineering Lead)
- Based on customer feedback and technical analysis

## Implementation Date
2025-06-30

## Validation Results

### Technical Validation ✅
- 170 patterns loading correctly (previously showed 429 due to tier multiplication)
- Memory usage reduced by ~75%
- API endpoints responding correctly
- RSOLV-action compatibility verified

### Business Validation ✅
- Simpler pricing model: $15/fix regardless of pattern complexity
- Clearer value proposition: Demo vs full access
- Better customer onboarding experience
- Maintained all functionality while reducing complexity

This ADR represents a significant simplification of RSOLV's architecture while maintaining full functionality and improving performance.