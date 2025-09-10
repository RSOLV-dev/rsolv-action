# ADR-025: Distributed Rate Limiting with Mnesia

**Status**: Implemented  
**Date**: 2025-09-10  
**RFC**: RFC-054  

## Context

Our rate limiting system previously used local ETS tables with periodic synchronization between nodes every 5 seconds. This approach had several issues:
- Race conditions during the 5-second sync window where nodes could exceed global limits
- Complex merge logic required to reconcile divergent counts
- Potential for denial of service if sync messages overwhelmed the system
- No guarantee of consistency across the cluster

With our BEAM clustering infrastructure in place (ADR-006), we needed a truly distributed solution that provides immediate consistency across all nodes.

## Decision

Migrated from ETS-based rate limiting to Mnesia distributed database for the following reasons:

1. **Strong Consistency**: Mnesia transactions ensure all nodes see the same rate limit counts immediately
2. **Built-in Replication**: Automatic table replication to all cluster nodes
3. **Fault Tolerance**: Continues to work even if nodes join/leave the cluster
4. **Simplified Code**: Removed complex merge logic and sync intervals

### Implementation Details

- **Storage Type**: Using `ram_copies` instead of `disc_copies` because:
  - Rate limits are ephemeral (60-second windows)
  - Kubernetes environments may have restricted filesystem access
  - No need to persist data across restarts
  
- **Table Management**: 
  - Automatic table creation on node startup
  - Retry logic for handling inactive nodes during creation
  - Node monitoring to replicate tables when new nodes join

- **Fail-Open Behavior**: On transaction failures, allow requests through rather than blocking
  - Maintains availability over strict enforcement
  - Logs failures for monitoring

## Consequences

### Positive
- **Eliminated Race Conditions**: True distributed consistency across all nodes
- **Improved Performance**: No more 5-second sync delays or merge operations  
- **Simplified Maintenance**: Mnesia handles replication automatically
- **Better Observability**: Enhanced health endpoint shows both BEAM and Mnesia clustering status

### Negative
- **Mnesia Learning Curve**: Team needs to understand Mnesia operations
- **Schema Management**: Must handle schema creation and table management on startup
- **Network Partitions**: Split-brain scenarios require careful consideration (mitigated by fail-open)

### Neutral
- **No Disk Persistence**: Rate limits reset on full cluster restart (acceptable for 60-second windows)
- **Memory Usage**: Similar to ETS but replicated across all nodes

## Implementation Notes

### Production Issues Resolved
1. **Mix.env() Runtime Error**: Removed compile-time environment checks that broke in releases
2. **Filesystem Permissions**: Switched from disc_copies to ram_copies for Kubernetes compatibility
3. **Table Creation Failures**: Added retry logic for handling temporarily inactive nodes
4. **Critical Configuration Issues** (2025-09-10): 
   - **Phoenix SECRET_KEY_BASE Missing**: Production deployment failed due to 0-byte secret key
   - **LiveView Signing Salt Missing**: Missing configuration caused 500 errors
   - **Mnesia Node Name Issues**: Resolved `:nonode@nohost` initialization problems with cleanup logic
5. **Health Check False Positives** (2025-09-10):
   - **Fixed Mnesia Status Logic**: Corrected false "warning" status in healthy 2-node clusters
   - **Enhanced Configuration Validation**: Added comprehensive Phoenix configuration checks to prevent future outages

### Health Check Enhancements
Added comprehensive Mnesia status and Phoenix configuration validation to `/health` endpoint:
```json
{
  "status": "ok",
  "mnesia": {
    "status": "ok",
    "running": true,
    "running_db_nodes": ["rsolv@10.42.5.177", "rsolv@10.42.11.82"],
    "configured_db_nodes": ["rsolv@10.42.5.177", "rsolv@10.42.11.82"],
    "tables": ["schema", "rsolv_rate_limiter", "fun_with_flags_toggles"],
    "rate_limiter_table": {
      "exists": true,
      "ram_copies": ["rsolv@10.42.5.177", "rsolv@10.42.11.82"],
      "disc_copies": [],
      "size": 0
    }
  },
  "phoenix_config": {
    "status": "ok",
    "secret_key_configured": true,
    "secret_key_base_length": 64,
    "live_view_salt_configured": true,
    "live_view_salt_length": 16,
    "endpoint_configured": true,
    "issues": [],
    "warnings": [],
    "message": "Phoenix configuration is healthy"
  }
}
```

This enhanced monitoring immediately surfaces critical configuration issues that could cause production outages, preventing the SECRET_KEY_BASE and LiveView salt issues we encountered.

## Testing

Comprehensive test coverage includes:
- Basic rate limiting functionality preserved
- Table replication across nodes
- Mnesia accessibility after node restart
- Automatic replication when nodes join cluster

## Monitoring

Key metrics to monitor:
- Mnesia transaction failures (should be rare)
- Table replication lag (should be immediate)
- Memory usage of rate limiter table
- Node join/leave events and table replication

## References

- [Mnesia Documentation](https://www.erlang.org/doc/apps/mnesia/mnesia.html)
- [BEAM Clustering (ADR-006)](./ADR-006-BEAM-CLUSTERING.md)
- [RFC-054: Distributed Rate Limiter](../RFCs/RFC-054-DISTRIBUTED-RATE-LIMITER.md)