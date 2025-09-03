# RFC-045: False Positive Caching System

**Status**: COMPLETE - Deployed to Production ✅  
**Created**: 2025-08-16  
**Updated**: 2025-08-17  
**Completed**: 2025-08-17  
**Deployed to Staging**: 2025-08-17 00:00  
**Deployed to Production**: 2025-08-17 07:30  
**Author**: Platform Team  

## Summary

Implement platform-side caching of false positive validation results to prevent redundant re-validation of known false positives, reducing compute costs and improving scan performance.

## Problem Statement

Currently, every scan/validation cycle fully re-validates all detected vulnerabilities, even those previously determined to be false positives. This causes:
- Unnecessary API calls to AST validation service (70-90% are re-validating false positives)
- Wasted compute time (30-60s per issue that could be 1-2s)
- Redundant GitHub issues for known false positives
- Poor user experience with repeated false alarms

## Solution Design

### Core Architecture

Platform-side caching with the platform as the single source of truth:
- Cache validation results when false positives are identified
- Check cache before performing expensive AST validation
- Invalidate cache when files change
- 90-day TTL as safety net

### Key Design Decisions

#### 7. Cache Scope: Forge-Account Isolated
**Decision**: Cache is scoped to forge_accounts (GitHub organizations)
**Rationale**:
- Security: No information leakage between organizations
- Privacy: Competitors don't see each other's scanning activity
- Isolation: Cache poisoning limited to your own organization
- Alignment: Fits existing forge_account authorization model
- Business model: Clear usage boundaries per customer

#### 8. Storage Backend: PostgreSQL via Ecto
**Decision**: Use existing PostgreSQL database with Ecto
**Rationale**:
- No new infrastructure required
- ACID guarantees for cache consistency
- Can JOIN with existing tables (repositories, forge_accounts)
- JSONB perfect for storing validation results
- Ecto provides migrations, schemas, validations
- Simple testing with sandbox mode
- 90-day TTL appropriate for database storage, not memory cache

### Key Design Decisions

#### 1. Cache Location: Platform-Side
**Decision**: Cache exclusively on the platform side
**Rationale**: 
- API calls to platform are cheap
- Single source of truth
- No client-side cache synchronization issues

#### 2. Cache Key Structure: Location-Based
**Decision**: Use location-based keys with all files sorted
```
"RSOLV-dev/nodegoat/[app/routes/profile.js:42]:sql-injection"
```
**Rationale**:
- Simple and deterministic
- Perfect debugging (human-readable)
- Our aggressive invalidation strategy (ANY file change) makes complex hashing unnecessary

#### 3. Invalidation Strategy: Conservative
**Decision**: Invalidate cache when ANY change is made to the file
**Rationale**:
- Prefer false negatives over false positives (safety first)
- Simple to implement and reason about
- Can relax in future versions

#### 4. Change Detection: File Content Hash
**Decision**: Use SHA-256 hash of file contents
**Rationale**:
- Works identically in CI/CD and local development
- No git dependency
- Deterministic and simple

#### 5. API Structure: Arrays from Day One
**Decision**: Use arrays for file locations even in v1 (single-file only)
```typescript
{
  vulnerabilities: [{
    type: "sql-injection",
    locations: [{  // Array even with single element in v1
      file_path: "app/routes/profile.js",
      line: 42,
      is_primary: true
    }],
    file_hashes: {
      "app/routes/profile.js": "sha256:abc..."
    }
  }]
}
```
**Rationale**:
- Zero migration when adding multi-file support
- Data model correctly represents reality from day one
- No breaking changes needed for v2

#### 6. Observability: Basic Metrics
**Decision**: Include cache metadata and basic logging
**Response includes**:
- `fromCache: true/false`
- `cachedAt: timestamp`
- `cacheKey: string`
- Cache hit/miss logs
**Rationale**:
- Essential for debugging production issues
- Minimal overhead (just passing through data we already have)

### API Contract

#### Request (RSOLV-action → Platform)
```typescript
POST /api/v1/ast/validate
{
  vulnerabilities: [{
    type: "sql-injection",
    locations: [{
      file_path: "app/routes/profile.js",
      line: 42,
      is_primary: true
    }]
  }],
  files: {
    "app/routes/profile.js": {
      content: "full file content...",
      hash: "sha256:abc123..."
    }
  },
  repository: "RSOLV-dev/nodegoat"
}
```

#### Response (Platform → RSOLV-action)
```typescript
{
  validated: [{
    id: "generated-id",
    isValid: false,  // false = it's a false positive
    confidence: 0.95,
    reason: "No user input flow detected",
    
    // Cache metadata when applicable
    fromCache: true,
    cachedAt: "2025-08-16T10:30:00Z",
    cacheKey: "forge_123/RSOLV-dev/nodegoat/[app/routes/profile.js:42]:sql-injection",
    cacheScope: "organization"  // vs "community" in future
  }],
  stats: {
    total: 1,
    validated: 0,
    rejected: 1,
    cacheHits: 1
  }
}
```

### Data Storage Schema

```typescript
interface CachedValidation {
  cache_key: string;  // "forge_account_id/repo/[files]:type"
  forge_account_id: number;  // Scope isolation
  repository: string;
  vulnerability_type: string;
  locations: Array<{file_path: string, line: number}>;
  file_hashes: Record<string, string>;
  
  // Validation result
  is_false_positive: boolean;
  confidence: number;
  reason: string;
  
  // Metadata
  cached_at: Date;
  ttl_expires_at: Date;  // 90 days from cached_at
  invalidated_at?: Date;
  invalidation_reason?: 'file_change' | 'ttl_expired' | 'manual';
}
```

## Implementation Status

### Completed (TDD Cycles) ✅
- ✅ **Cycle 1**: Cache key generation (100% tested, 6 tests)
  - Deterministic key generation with sorted locations
  - Forge-account scoping working correctly
- ✅ **Cycle 2**: Cache storage (100% tested, 8 tests)
  - PostgreSQL/Ecto integration complete
  - Upsert semantics with ID preservation
  - TTL automatically set to 90 days
- ✅ **Cycle 3**: Cache retrieval (100% tested, 8 tests)
  - File hash validation working
  - TTL expiration checking implemented
  - Returns proper status atoms for analytics
- ✅ **Cycle 4**: Cache invalidation (100% tested, 9 tests)
  - Single and bulk invalidation working
  - JSONB array queries for file-based invalidation
  - Proper isolation between forge accounts
- ✅ **Cycle 5**: Integration tests (100% tested, 8 tests)
  - Complete workflow validation
  - Performance characteristics verified
  - Cache statistics tracking implemented

### Test Coverage Summary
- **Total Tests**: 39 passing
- **Coverage**: 100% of cache modules
- **Performance**: <10ms lookups with 1000+ entries

### Implementation Learnings
1. **Ecto upsert**: Need `{:replace_all_except, [:id]}` to preserve IDs on updates
2. **Testing isolation**: Each test needs unique forge accounts to avoid conflicts
3. **Pipeline style**: Elixir pipeline operator improves readability for cache lookups
4. **Status atoms**: Using different atoms (`:miss`, `:expired`, `:invalidated`) enables better analytics

## Implementation Plan

### Phase 1: Basic Caching (MVP)
1. Modify platform AST validation endpoint to check cache first
2. Store false positive results with diagnostic data
3. Include cache metadata in responses
4. Add file hash validation
5. Implement 90-day TTL
6. Add cache hit/miss logging

### Phase 2: Monitoring & Optimization
1. Add metrics dashboard (hit rate, common patterns)
2. Analyze cache effectiveness
3. Consider relaxing invalidation rules for specific file types
4. Add cache management endpoints if needed

### Phase 3: Multi-File Support (Future)
1. Extend locations array to include multiple files
2. Update cache key generation to include all files
3. Invalidate if ANY involved file changes
4. Track cross-file vulnerability patterns

## Testing Strategy

### Unit Tests
- Cache key generation with various inputs
- File hash computation and comparison
- TTL expiration logic
- Cache invalidation on file change

### Integration Tests
- Full flow: scan → cache miss → validate → store
- Full flow: scan → cache hit → return cached
- File change → cache invalidation → revalidation
- TTL expiration after 90 days

### Performance Tests
- Measure reduction in AST API calls
- Measure scan time improvement
- Monitor cache size growth over time

## Success Metrics

1. **Cache hit rate**: Target 70%+ for mature repositories
2. **Performance improvement**: 60-80% reduction in validation time
3. **Cost reduction**: 70-90% fewer AST API calls
4. **User experience**: 90% reduction in duplicate false positive issues

## Rollout Plan

1. Deploy to staging with feature flag
2. Test with internal repositories
3. Enable for select beta customers
4. Monitor metrics for 2 weeks
5. General availability

## Future Enhancements

### Phase 2: Community Cache for FOSS

Add optional repository-scoped caching for popular open-source packages:

```typescript
// Hybrid cache lookup
async function checkCache(repo, location, vulnType, forgeAccount) {
  // 1. Check organization cache first (most trusted)
  const orgCache = await getOrgCache(forgeAccount, repo, location, vulnType);
  if (orgCache) return { ...orgCache, cacheScope: 'organization' };
  
  // 2. Check community cache for eligible FOSS repos
  if (isEligibleForCommunityCache(repo) && settings.useCommunityCache) {
    const communityCache = await getCommunityCache(repo, location, vulnType);
    if (communityCache) return { ...communityCache, cacheScope: 'community' };
  }
  
  return null;
}
```

**Benefits**:
- Popular FOSS packages validated once
- Community intelligence sharing
- Opt-in for privacy control
- Clear trust indicators

**Implementation**:
1. Start with allowlist of top 100 FOSS packages
2. Read-only community cache initially
3. Later: reputation-based contribution system

### Other Future Enhancements

1. **Relaxed invalidation**: Only invalidate if specific lines change
2. **Cross-repository learning**: Share false positive patterns (opt-in)
3. **ML-based confidence**: Use historical data to improve confidence scores
4. **User feedback loop**: Learn from manual false positive corrections
5. **Multi-file vulnerability support**: Extend to cross-file patterns

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Caching real vulnerabilities | Conservative invalidation, 90-day TTL |
| Cache size growth | TTL expiration, monitoring |
| Complex debugging | Rich cache metadata in responses |
| Breaking changes for multi-file | Arrays from day one |

## Decision Log

1. **Platform-side caching**: Simpler than distributed caching
2. **Location-based keys**: Optimal given aggressive invalidation
3. **File content hash**: Universal solution (no git dependency)
4. **Arrays from day one**: Prevents future breaking changes
5. **90-day TTL**: Safety net for edge cases

## References

- RFC-044: Phase Data Persistence (prerequisite infrastructure)
- AST Validation Service Documentation
- False Positive Analysis Report (internal)

## Implementation Notes

### Production Deployment (2025-08-17)

**Deployed to Production**: 07:30 MDT
- Image: `ghcr.io/rsolv-dev/rsolv-platform:staging-detector-fix-20250816-212842`
- Migration: `20250817000713_create_cached_validations` executed successfully
- Configuration: `FORCE_CACHE_CONTROLLER=true` environment variable
- Monitoring: Both Grafana dashboards deployed and accessible

**Results**:
- ✅ 100% cache hit rate for false positives in testing
- ✅ <50ms response times for cached results
- ✅ Zero false negatives - all real vulnerabilities detected
- ✅ Production deployment successful with zero downtime

**Dashboard URLs**:
- Production: https://grafana.rsolv.dev/d/fp-cache-production
- Staging: https://grafana.rsolv.dev/d/fp-cache-staging

### Database Schema (As Implemented)

```elixir
# Actual Ecto migration
create table(:cached_validations) do
  add :cache_key, :text, null: false
  add :forge_account_id, references(:forge_accounts, on_delete: :delete_all), null: false
  add :repository, :string, null: false
  add :vulnerability_type, :string, null: false
  add :locations, :jsonb, null: false  # Array of location maps
  add :file_hashes, :jsonb, null: false  # Map of path -> hash
  
  # Validation result
  add :is_false_positive, :boolean, null: false
  add :confidence, :decimal, null: false
  add :reason, :text
  add :full_result, :jsonb
  
  # Metadata
  add :cached_at, :utc_datetime_usec, null: false
  add :ttl_expires_at, :utc_datetime_usec, null: false
  add :invalidated_at, :utc_datetime_usec
  add :invalidation_reason, :string
  
  timestamps(type: :utc_datetime_usec)
end

# Indexes for performance
create unique_index(:cached_validations, [:cache_key])
create index(:cached_validations, [:forge_account_id])
create index(:cached_validations, [:repository])
create index(:cached_validations, [:ttl_expires_at])
create index(:cached_validations, [:forge_account_id, :repository])
```

### V1 Limitations (Deliberate)
- Single-file vulnerabilities only
- No cross-file pattern detection
- Conservative invalidation (any change invalidates)
- Fixed 90-day TTL

These limitations are intentional for v1 simplicity and will be addressed in future versions based on production learnings.

## Appendix: Example Cache Flow

1. **First Scan**:
   - Detect potential SQL injection at profile.js:42
   - Cache key: `"RSOLV-dev/nodegoat/[app/routes/profile.js:42]:sql-injection"`
   - Check cache: MISS
   - Run AST validation: Determines false positive
   - Store in cache with file hash

2. **Second Scan** (no changes):
   - Detect same potential SQL injection
   - Generate same cache key
   - Check cache: HIT
   - Return cached result (1-2s vs 30-60s)

3. **Third Scan** (file modified):
   - File hash changed
   - Cache invalidated
   - Run full validation again
   - Update cache with new result

## Deployment Status

### Staging Deployment (2025-08-17)

**Status**: ✅ Successfully Deployed, Load Tested, and Ready for Production!

**What's Complete**:
- ✅ All 39 unit tests passing for cache functionality
- ✅ Cache module fully implemented with 100% test coverage
- ✅ API integration complete with feature flag router
- ✅ Database migrations successful
- ✅ Cache functionality verified in staging (100% hit rate for false positives)
- ✅ Environment variable override implemented (`FORCE_CACHE_CONTROLLER=true`)
- ✅ Comprehensive validation test suite created (300+ test cases)
- ✅ SafePatternDetector fixed for all vulnerability types
- ✅ Load testing completed with excellent results

**Cache Performance Verified**:
- **Hit Rate**: 100% for repeated requests with unchanged files
- **Response Time**: <50ms for cache hits (vs 500-1000ms for misses)
- **Invalidation**: Correctly detects file changes via hash comparison
- **TTL**: 89.5 days as configured
- **Isolation**: Forge-account scoped working correctly
- **Metadata**: All cache fields present (`fromCache`, `cachedAt`, `cacheKey`, `cacheHitType`)

**FunWithFlags Issue - Root Cause Identified**:
1. ETS cache starts empty at application startup
2. First flag check returns default `false` (not from database)
3. This `false` value gets cached in ETS
4. Database value (`true`) is never read until cache expires

**Solutions Available**:
1. **Current Workaround**: Environment variable `FORCE_CACHE_CONTROLLER=true`
2. **Permanent Fix Option 1**: Warm cache on startup in application.ex
3. **Permanent Fix Option 2**: Configure cache TTL to force periodic refresh
4. **Permanent Fix Option 3**: Use FunWithFlags UI to toggle flag (triggers cache-bust)

**Test Scripts Created**:
- `monitor-cache-performance.sh` - Basic cache monitoring
- `test-known-false-positives.sh` - Validates false positive detection
- `test-real-vulnerabilities.sh` - Ensures real vulnerabilities detected
- `load-test-cache.sh` - Production-like load testing
- `test-validation-logic.exs` - Local validation logic testing

**Images Built**:
- `ghcr.io/rsolv-dev/rsolv-platform:staging-cache-env-20250816-205203` - With env var override
- `ghcr.io/rsolv-dev/rsolv-platform:staging-validation-fix-20250816-211313` - With initial validation fix
- `ghcr.io/rsolv-dev/rsolv-platform:staging-detector-fix-20250816-212842` - **CURRENT** - With complete SafePatternDetector fixes

**Production Readiness**:
- ✅ Cache logic working perfectly
- ✅ Performance targets met (<50ms, 100% hit rate)
- ✅ Validation accuracy verified with test suite
- ⚠️ FunWithFlags workaround in place (env var)
- 📋 24-hour staging test recommended before production

**Next Steps**:
1. Deploy validation fix image to staging
2. Run 24-hour load test with real-like traffic
3. Monitor cache metrics and performance
4. Set up Grafana dashboards
5. Plan production rollout with rollback strategy

**Key Learnings**:
- Cache implementation is solid and performant
- FunWithFlags ETS cache behavior needs documentation
- Environment variables provide reliable feature flag override
- Comprehensive test coverage is essential for validation logic
- Phoenix.PubSub works perfectly without Redis
- Cache design correctly focuses on false positives only (not real vulnerabilities)
- SafePatternDetector requires careful regex design to avoid false negatives
- Load testing confirms 100% hit rate for unchanged false positives

**Load Test Results (2025-08-17)**:
- Tested with 100+ requests across 10 different false positive patterns
- **Cache hit rate**: 100% after initial priming
- **Response time**: Consistently <50ms for cached results
- **Concurrency**: Handles multiple simultaneous requests without issues
- **Cache size**: 10 entries after test (efficient storage)