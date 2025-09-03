# RFC-036: Server-side AST Validation

**RFC Number**: 036  
**Title**: Server-side AST Validation for False Positive Reduction  
**Author**: RSOLV Engineering Team  
**Status**: Implemented (Ready for Production)  
**Created**: 2025-07-01  

## Summary

Implement server-side AST validation in RSOLV-api to reduce false positives by 70-90% before issue creation. This validation will analyze vulnerabilities in their code context to determine if they are in comments, string literals, or other non-executable contexts.

## Motivation

Current vulnerability detection generates many false positives when patterns match code in:
- Comments explaining what not to do
- String literals in documentation
- Test assertions
- Educational content

This leads to:
- Noise in security reports
- Reduced developer trust
- Wasted AI fix attempts
- Higher operational costs

## Proposed Solution

### Architecture
1. **API Endpoint**: `/api/v1/vulnerabilities/validate`
2. **Integration Point**: Between pattern detection and issue creation
3. **Validation Logic**:
   - Check if code is in a comment
   - Check if code is in a string literal
   - Analyze surrounding context
   - Return confidence score (0.0-1.0)

### Implementation Phases

#### Phase 1: API Endpoint (✅ Completed)
- Create validation controller in RSOLV-api
- Support x-api-key and Bearer authentication
- Return validation results with confidence scores

#### Phase 2: Client Integration (✅ Completed)
- Add ASTValidator service to RSOLV-action
- Extend RsolvApiClient with validation method
- Configure enableASTValidation flag

#### Phase 3: Performance Optimization (✅ Completed)
- Add caching layer for repeated validations (✅ ValidationCache GenServer implemented)
- Implement batch processing (✅ Duplicate detection within batches)
- Add telemetry and metrics (✅ Cache hit/miss tracking)

#### Phase 4: Production Rollout (Ready)
- Enable by default (configuration already defaults to true)
- Monitor false positive reduction metrics
- Gather performance data for optimization

## Technical Details

### API Contract
```json
POST /api/v1/vulnerabilities/validate
Headers: 
  - x-api-key: {customer_api_key}
  - Content-Type: application/json

Request:
{
  "vulnerabilities": [
    {
      "id": "vuln-123",
      "patternId": "js-eval-injection",
      "filePath": "app.js",
      "line": 10,
      "code": "eval(userInput)",
      "severity": "critical"
    }
  ],
  "files": {
    "app.js": "// File contents here"
  }
}

Response:
{
  "validated": [
    {
      "id": "vuln-123",
      "isValid": true,
      "confidence": 0.95,
      "reason": null
    }
  ],
  "stats": {
    "total": 1,
    "validated": 1,
    "rejected": 0
  }
}
```

### Configuration
```yaml
- uses: RSOLV-dev/rsolv-action@main
  with:
    enable-ast-validation: true
    rsolv-api-key: ${{ secrets.RSOLV_API_KEY }}
```

## Implementation Status

### Completed ✅
- Phase 1: API endpoint implementation
- Phase 2: Client integration with ASTValidator service
- Phase 3: ValidationCache with ETS storage and TTL
- Phase 4: Production deployment (2025-07-17)
- Telemetry implementation with comprehensive metrics
- Grafana dashboard configuration
- Configuration support with default enabled
- Authentication support (x-api-key and Bearer)
- Comprehensive test coverage

### Production Deployment Details
- **Production Endpoint**: https://api.rsolv.ai/api/v1/vulnerabilities/validate
- **Staging Endpoint**: https://api.rsolv-staging.com/api/v1/vulnerabilities/validate
- **Cache TTL**: 5 minutes (configurable)
- **Telemetry Events**: 
  - `[:rsolv, :validation, :request]` - Request metrics
  - `[:rsolv, :validation, :false_positive]` - False positive tracking
  - `[:rsolv, :validation, :cache_hit/miss]` - Cache effectiveness

### Telemetry Implementation
- **Module**: `RsolvWeb.Telemetry.ValidationTelemetry`
- **Reporter**: `Rsolv.Telemetry.ValidationReporter`
- **Metrics**: Duration, false positive rate, cache hit rate, pattern rejection counts
- **Dashboard**: Available at `/shared/monitoring/ast-validation-dashboard.json`

## Success Metrics

- **Target**: 70-90% false positive reduction
- **Performance**: < 100ms per vulnerability
- **Availability**: 99.9% uptime
- **Adoption**: 100% of scans using validation by Q2 2025

## Alternatives Considered

1. **Client-side only validation**: Rejected due to:
   - Code duplication across clients
   - Harder to update logic
   - Missing server-side insights

2. **ML-based approach**: Deferred to future phase due to:
   - Training data requirements
   - Complexity
   - Time to market

3. **Static analysis tools**: Rejected due to:
   - Language-specific implementations
   - Integration complexity
   - Maintenance burden

## Open Questions (Resolved)

1. ~~Should we cache validation results permanently or with TTL?~~ → Implemented with 5-minute TTL
2. ~~What's the optimal batch size for validation requests?~~ → Start with current implementation, optimize based on metrics
3. ~~Should we collect anonymous metrics on rejected patterns?~~ → Yes, implement in monitoring phase

## Monitoring Plan

### Key Metrics to Track

1. **False Positive Reduction Rate**
   - Metric: `ast_validation.false_positive_rate`
   - Target: 70-90% reduction
   - Formula: (rejected_vulnerabilities / total_vulnerabilities) * 100

2. **API Performance**
   - Metric: `ast_validation.response_time`
   - Target: < 100ms per vulnerability
   - Track: p50, p95, p99 latencies

3. **Cache Effectiveness**
   - Metrics: `validation_cache.hit_rate`, `validation_cache.miss_rate`
   - Target: > 80% hit rate for repeated scans

4. **System Health**
   - Metric: `ast_validation.availability`
   - Target: 99.9% uptime
   - Track: Success/failure rates, timeout rates

### Implementation Dashboard

```elixir
# Telemetry events to emit
:telemetry.execute(
  [:rsolv, :validation, :request],
  %{duration: duration, vulnerabilities_count: count},
  %{result: :success | :failure, cached: boolean()}
)

:telemetry.execute(
  [:rsolv, :validation, :false_positive],
  %{rejected_count: rejected, total_count: total},
  %{customer_id: customer_id, pattern_ids: pattern_ids}
)
```

### Monitoring Tools

1. **Grafana Dashboard**
   - False positive reduction trends
   - API response time graphs
   - Cache hit rate visualization
   - Customer adoption metrics

2. **Alerts**
   - API response time > 500ms (warning)
   - API response time > 1000ms (critical)
   - Cache hit rate < 50% (warning)
   - API availability < 99% (critical)

3. **Weekly Reports**
   - False positive reduction by pattern type
   - Performance trends
   - Customer adoption rate
   - Most commonly rejected patterns

## References

- [ADR-012: In-place Vulnerability Fixes](../ADRs/ADR-012-IN-PLACE-VULNERABILITY-FIXES.md)
- [RFC-032: Pattern API JSON Migration](RFC-032-PATTERN-API-JSON-MIGRATION.md)
- [RFC-031: Elixir AST Analysis Service](RFC-031-ELIXIR-AST-ANALYSIS-SERVICE.md)

## Production Deployment Steps

1. **Pre-deployment Checklist**
   - [ ] Verify staging endpoint is stable
   - [ ] Confirm ValidationCache is working correctly
   - [ ] Review error handling and fallback behavior
   - [ ] Ensure monitoring telemetry is in place

2. **Deployment Process**
   ```bash
   # Deploy RSOLV-api with validation endpoint
   cd ~/dev/rsolv/RSOLV-platform
   ./deploy.sh production
   
   # Verify endpoint is live
   curl -X POST https://api.rsolv.ai/api/v1/vulnerabilities/validate \
     -H "x-api-key: $TEST_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"vulnerabilities": [], "files": {}}'
   ```

3. **Post-deployment Verification**
   - [ ] Run test scan with known false positives
   - [ ] Verify cache is functioning
   - [ ] Check telemetry data is flowing
   - [ ] Monitor error rates for first 24 hours

4. **Gradual Rollout** (if desired)
   - Use feature flags to enable for specific customers first
   - Monitor metrics before full rollout
   - Document any issues or performance concerns

## Implementation Tracking

- Implementation completed: 2025-07-17
- Staging deployment: Complete with telemetry
- Production deployment: Complete (2025-07-17)
- Telemetry deployment: Staging complete, production pending
- Monitoring dashboard: Created, pending Grafana deployment

## Testing Results

Testing and validation results will be documented here as they are collected.