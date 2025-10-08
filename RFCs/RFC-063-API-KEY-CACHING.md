# RFC-063: API Key Caching with Mnesia

**Status**: Draft
**Date**: 2025-10-07
**Author**: Claude (System)
**Related**: ADR-025 (Distributed Rate Limiting with Mnesia), ADR-027 (Centralized API Authentication)

## Context

The RSOLV platform currently experiences database connection pool exhaustion under concurrent load due to uncached API key validation. Each API request performs 2 database queries:

1. `Accounts.get_customer_by_api_key(api_key)` - Lookup customer record
2. `Customers.get_api_key_by_key(api_key)` - Fetch API key metadata

### Problem Statement

**Observed Behavior:**
- Test suite with 8 parallel shards fails with `SyntaxError: Unexpected end of JSON input` (truncated responses)
- Database pool size: 10 connections
- Each pattern API request consumes 2 DB connections temporarily
- No caching of API key lookups
- 95%+ of requests use the same API key (especially in test environments)

**Impact:**
- Test suite reliability issues
- Potential production performance degradation under load
- Inefficient use of database resources
- Poor response times for authenticated requests

### Current Architecture

```elixir
# lib/rsolv_web/plugs/api_authentication.ex
defp authenticate_with_key(conn, api_key, optional?) do
  case Accounts.get_customer_by_api_key(api_key) do  # DB Query #1
    nil -> handle_invalid_key(conn, optional?)
    customer ->
      api_key_record = Rsolv.Customers.get_api_key_by_key(api_key)  # DB Query #2
      conn
      |> assign(:customer, customer)
      |> assign(:api_key, api_key_record)
  end
end
```

## Proposal

Implement distributed API key caching using Mnesia, following the architectural patterns established in ADR-025 (Distributed Rate Limiting).

### Architecture

```elixir
defmodule Rsolv.Customers.ApiKeyCache do
  use GenServer

  @table_name :api_key_cache
  @ttl_seconds 300  # 5 minutes

  # Cache structure: {api_key, customer_id, customer_active, api_key_record_id, expires_at}
  # Mnesia ram_copies for cluster-wide consistency
end
```

### Key Design Decisions

1. **Storage Type**: `ram_copies` (not `disc_copies`)
   - API keys are not critical for persistence
   - Kubernetes environments may restrict filesystem access
   - Cache can be rebuilt on restart (acceptable 5-minute TTL)
   - Follows ADR-025 pattern for ephemeral data

2. **TTL**: 5 minutes
   - Balances freshness with performance
   - Allows key revocations to propagate reasonably quickly
   - Reduces DB load by ~95% for steady-state traffic

3. **Cache Key Format**: Simple string (the API key itself)
   - No complex key generation needed
   - Natural uniqueness guaranteed

4. **Invalidation Strategy**:
   - **Time-based**: 5-minute TTL enforced by cache lookup
   - **Event-based**: Invalidate on API key update/delete via PubSub
   - **Manual**: Admin RPC command for cache clearing

5. **Fail-Through Behavior**: On cache miss or error, query database
   - Maintains availability over strict enforcement
   - Logs cache misses for monitoring

### Implementation Phases

#### Phase 1: Core Cache Implementation (4-6 hours)

**Tasks:**
- Create `lib/rsolv/customers/api_key_cache.ex` GenServer
- Implement Mnesia table management (following ADR-025)
- Add cache lookup with TTL validation
- Add cache insertion after successful DB lookup
- Add event-based invalidation (API key updates/deletes)

**Acceptance Criteria:**
- Cache table created on application startup
- Automatic replication across cluster nodes
- TTL enforced on cache reads
- Cache hit/miss logged for monitoring

#### Phase 2: Integration with ApiAuthentication (2-3 hours)

**Tasks:**
- Modify `lib/rsolv_web/plugs/api_authentication.ex`
- Add cache lookup before DB query
- Insert to cache after successful DB authentication
- Add telemetry events for cache metrics

**Acceptance Criteria:**
- Cache reduces DB queries by 95%+ for repeat keys
- No change to authentication behavior (same security guarantees)
- Graceful degradation on cache failures
- Unit tests for cache integration

#### Phase 3: Monitoring & Observability (2-3 hours)

**Tasks:**
- Extend `/health` endpoint with cache status
- Add Prometheus metrics:
  - `api_key_cache_hits_total`
  - `api_key_cache_misses_total`
  - `api_key_cache_size`
  - `api_key_cache_evictions_total`
- Create Grafana dashboard
- Add alerts for low hit rates (<80%)

**Acceptance Criteria:**
- Health endpoint shows cache table status
- Metrics exported to Prometheus
- Dashboard visualizes cache performance
- Alert fires if hit rate drops below threshold

#### Phase 4: Performance Testing (2-3 hours)

**Tasks:**
- Run RSOLV-action test suite with cache enabled
- Load test with 20+ concurrent requests
- Test cluster node failure scenarios
- Document performance improvements

**Test Scenarios:**
- 8 parallel test shards (current failure scenario)
- Mix of cached and uncached keys
- Node joins/leaves cluster during load
- Cache invalidation during high traffic

**Acceptance Criteria:**
- Test suite passes with 8 parallel shards
- DB pool usage stays below 60%
- Cache hit rate > 95% for steady-state
- Performance metrics documented

#### Phase 5: Documentation (1-2 hours)

**Tasks:**
- Create ADR-028: API Key Caching with Mnesia
- Update API authentication documentation
- Add runbook for cache operations
- Document cache metrics and alerts

**Acceptance Criteria:**
- ADR follows established template
- References ADR-025 and ADR-027
- Includes performance results
- Runbook covers common operations

### Database Schema Impact

**No database schema changes required** - this is a pure caching layer.

### Mnesia Table Structure

```elixir
# Table: :api_key_cache
# Type: :set (unique keys)
# Storage: :ram_copies
# Attributes: [:api_key, :customer_id, :customer_active, :api_key_record_id, :inserted_at]

defmodule Rsolv.Customers.ApiKeyCache.Record do
  @moduledoc """
  Mnesia record for API key cache.
  """

  defstruct [
    :api_key,           # String - The API key (primary key)
    :customer_id,       # UUID - Customer ID
    :customer_active,   # Boolean - Is customer active?
    :api_key_record_id, # UUID - API key record ID
    :inserted_at        # DateTime - Cache insertion time (for TTL)
  ]
end
```

### Code Changes

**Files to Create:**
- `lib/rsolv/customers/api_key_cache.ex` - GenServer with Mnesia table management

**Files to Modify:**
- `lib/rsolv_web/plugs/api_authentication.ex` - Add cache lookup
- `lib/rsolv/application.ex` - Add to supervision tree
- `lib/rsolv_web/controllers/page_controller.ex` - Extend health check
- `config/config.exs` - Cache configuration (TTL, etc.)

**Files for Testing:**
- `test/rsolv/customers/api_key_cache_test.exs` - Unit tests
- `test/rsolv_web/plugs/api_authentication_test.exs` - Integration tests

## Alternatives Considered

### 1. PostgreSQL-based Caching (Rejected)

**Pros:**
- Persistent across restarts
- Familiar query patterns

**Cons:**
- Doesn't solve the DB connection pool problem
- Adds another table to query
- No distribution without additional complexity

### 2. ETS Local Caching (Rejected)

**Pros:**
- Simple implementation
- Fast local lookups

**Cons:**
- Not distributed - cache per node
- Inconsistent across cluster
- Doesn't leverage existing Mnesia infrastructure

### 3. Redis External Cache (Rejected)

**Pros:**
- Battle-tested caching solution
- Rich feature set

**Cons:**
- Additional infrastructure dependency
- Network latency for cache lookups
- Operational complexity
- Against our "minimal dependencies" principle

### 4. Mnesia with `disc_copies` (Rejected)

**Pros:**
- Survives restarts

**Cons:**
- Filesystem access issues in Kubernetes (ADR-025 experience)
- Not necessary for 5-minute TTL data
- Performance overhead

## Performance Expectations

### Before (No Caching)

- **DB Queries per Auth**: 2
- **Test Suite (8 shards)**: Pool exhaustion, failures
- **Production Load**: Potential slowdowns under traffic spikes

### After (With Caching)

- **DB Queries per Auth**: 0.05 (95% cache hit rate)
- **Cache Lookup Time**: <1ms (in-memory)
- **DB Pool Usage**: Reduced by 95%
- **Test Suite**: Passes reliably with 8+ parallel shards
- **Production**: Handles 10x traffic with same pool size

### Metrics to Track

- Cache hit rate (target: >95%)
- Cache miss rate
- Average cache lookup time
- DB connection pool utilization
- API authentication response time
- Cache memory usage

## Risks and Mitigations

### Risk 1: Stale Data After Key Revocation

**Impact**: Medium - Revoked keys may work for up to 5 minutes

**Mitigation**:
- Event-based cache invalidation via PubSub
- 5-minute TTL is acceptable for security (similar to JWT exp times)
- Manual cache clear command for emergency revocations

### Risk 2: Memory Usage in Large Deployments

**Impact**: Low - Typical deployment has <100 active API keys

**Mitigation**:
- Monitor cache size via metrics
- TTL automatically evicts old entries
- Configurable max cache size if needed

### Risk 3: Mnesia Split-Brain Scenarios

**Impact**: Low - Cached data is ephemeral

**Mitigation**:
- Same split-brain handling as rate limiter (ADR-025)
- Fail-through to DB on cache errors
- Cache rebuilds automatically after partition heals

### Risk 4: Cache Warming on Cold Start

**Impact**: Low - First request per key hits DB

**Mitigation**:
- Natural warming through normal traffic
- Optional pre-warming script for known keys
- Acceptable cold-start performance (single DB query)

## Success Criteria

1. **Performance**: RSOLV-action test suite passes with 8+ parallel shards
2. **Reliability**: 0 test failures due to API pool exhaustion
3. **Efficiency**: DB connection pool usage <60% under test load
4. **Hit Rate**: Cache hit rate >95% for steady-state traffic
5. **Monitoring**: All metrics exposed and dashboard created
6. **Documentation**: ADR-028 created with implementation details

## Timeline Estimate

**Total**: 11-17 hours

- Phase 1 (Core): 4-6 hours
- Phase 2 (Integration): 2-3 hours
- Phase 3 (Monitoring): 2-3 hours
- Phase 4 (Testing): 2-3 hours
- Phase 5 (Documentation): 1-2 hours

## Dependencies

- ADR-025: Distributed Rate Limiting (Mnesia patterns established)
- ADR-027: Centralized API Authentication (current implementation)
- Existing Mnesia infrastructure (clustering, table management)

## References

- [Mnesia Documentation](https://www.erlang.org/doc/apps/mnesia/mnesia.html)
- [ADR-025: Distributed Rate Limiting](../ADRs/ADR-025-DISTRIBUTED-RATE-LIMITING-WITH-MNESIA.md)
- [ADR-027: Centralized API Authentication](../ADRs/ADR-027-CENTRALIZED-API-AUTHENTICATION.md)
- [BEAM Clustering (ADR-006)](../ADRs/ADR-006-BEAM-CLUSTERING.md)
