# ADR-025: Distributed Sessions with Mnesia

**Status:** Accepted  
**Date:** 2025-01-11  
**RFC:** Related to RFC-056 (Admin UI)

## Context

During the implementation of RFC-056 (Admin UI for Customer Management), we discovered that customer sessions were stored in ETS, which is node-local. This caused session persistence issues when:
- Pods restarted
- Load balancing distributed requests across multiple nodes
- BEAM clustering was enabled in Kubernetes

The system already had BEAM clustering configured with libcluster for Kubernetes, and Mnesia was available as a distributed database.

## Decision

Replace ETS session storage with Mnesia for distributed session management across the BEAM cluster.

## Implementation Details

1. **Created `Rsolv.CustomerSessions` module** - Dedicated GenServer for session management
2. **Mnesia table configuration**:
   - Table name: `:customer_sessions_mnesia`
   - Type: `:set` with `:ram_copies` for performance
   - Replicated across all nodes in the cluster
   - 7-day TTL with hourly cleanup process

3. **Fixed clustering configuration**:
   - Corrected service name from `staging-rsolv-headless` to `staging-rsolv-platform-headless`
   - Made configurable via `CLUSTER_SERVICE_NAME` environment variable

4. **No fallback mechanism** - Single implementation path (Mnesia only)

## Consequences

### Positive
- Sessions persist across pod restarts and deployments
- Load balancing works correctly with session affinity
- Automatic replication across cluster nodes
- No external dependencies (Redis, etc.)

### Negative
- Slightly more complex than ETS
- Requires BEAM clustering to be properly configured
- Memory usage scales with number of active sessions

### Neutral
- Sessions stored in RAM (ram_copies) for performance
- Automatic cleanup of expired sessions every hour

## Verification

Tested on staging with 2-node cluster:
- Sessions persist across pod restarts
- Admin login works correctly
- Mnesia tables properly replicated
- Rate limiting works as expected (10 attempts per minute)

## Notes

- Must set `CLUSTER_SERVICE_NAME` for production deployment
- Consider disc_copies if session persistence across full cluster restarts is needed
- Monitor memory usage as user base grows