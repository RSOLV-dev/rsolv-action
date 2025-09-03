# ADR-020: Phase Data Persistence Architecture

## Status
Accepted and Implemented (2025-08-15)

## Context
The three-phase security architecture (SCAN, VALIDATE, MITIGATE) required data persistence across different GitHub Action workflow runs. Without this, enriched validation data from the VALIDATE phase was lost when the MITIGATE phase ran in a separate workflow.

## Decision
Implement platform-side persistence for phase data using PostgreSQL with JSONB storage, enabling phases to access data from previous phases through secure API endpoints.

## Consequences

### Positive
- **Cross-Workflow Data Access**: MITIGATE phase can access VALIDATE's enriched data
- **Centralized Progress Tracking**: Complete visibility into security automation state
- **Performance Optimization**: Reduced redundant API calls between phases
- **Data Integrity**: Transactional guarantees for phase data updates
- **Multi-Tenant Isolation**: Forge-account scoped data access

### Negative
- **Storage Growth**: ~2KB per vulnerability, requires monitoring
- **API Complexity**: New endpoints for phase data management
- **Migration Path**: Existing workflows need updates to use persistence

## Implementation Details

### Data Model
```sql
phase_data
  - id: UUID (PK)
  - forge_account_id: UUID (FK)
  - repository: TEXT
  - issue_number: INTEGER
  - phase: ENUM('scan', 'validate', 'mitigate')
  - data: JSONB
  - created_at: TIMESTAMP
  - updated_at: TIMESTAMP
```

### API Endpoints
- `POST /api/v1/phase_data` - Store phase data
- `GET /api/v1/phase_data/:repository/:issue_number` - Retrieve phase data
- `DELETE /api/v1/phase_data/:repository/:issue_number` - Clean up after completion

### Security Model
- API key authentication required
- Forge account isolation enforced
- Read-only access for GET operations
- Write permissions verified per forge account

### Performance Metrics
- **Write Latency**: <50ms for phase data storage
- **Read Latency**: <30ms for phase data retrieval
- **Storage Efficiency**: 70% compression with JSONB
- **Query Performance**: Index on (forge_account_id, repository, issue_number)

### Production Deployment
- Deployed: 2025-08-15
- Zero downtime migration using Ecto
- Backwards compatible with non-persistent workflows
- Monitoring via application metrics

## References
- RFC-044: Phase Data Persistence Implementation
- RFC-041: Three-Phase Architecture
- ADR-011: Three-Phase Security Architecture