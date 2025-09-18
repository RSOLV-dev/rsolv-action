# Architecture Decision Records (ADR) Index

This directory contains Architecture Decision Records for the RSOLV project. ADRs document important architectural decisions that have been implemented and are in production use.

## ADR Template

Each ADR follows this structure:
- **Status**: Accepted/Implemented/Superseded
- **Context**: Problem being solved and constraints
- **Decision**: What was decided and why
- **Consequences**: What this enables and constrains

## Current ADRs

| ADR | Title | Status | Date | Impact |
|-----|-------|--------|------|---------|
| [ADR-001](ADR-001-CREDENTIAL-VENDING-ARCHITECTURE.md) | Credential Vending Architecture | Implemented | 2025-06-03 | High - Core competitive advantage |
| [ADR-002](ADR-002-WEBHOOK-INFRASTRUCTURE.md) | Webhook Infrastructure for Success-Based Billing | Implemented | 2025-06-03 | High - Enables business model |
| [ADR-003](ADR-003-SECURITY-FIRST-INTEGRATION.md) | Security-First Integration Architecture | Implemented | 2025-05-28 | High - Product differentiation |
| [ADR-004](ADR-004-MULTI-MODEL-AI-PROVIDER.md) | Multi-Model AI Provider Strategy | Implemented | 2025-05-25 | Medium - Foundation for expansion |
| [ADR-005](ADR-005-MULTI-REPOSITORY-ORGANIZATION.md) | Multi-Repository Organization | Implemented | 2025-05-20 | Medium - Development workflow |
| [ADR-006](ADR-006-BEAM-CLUSTERING.md) | BEAM Clustering for Horizontal Scalability | Implemented | 2025-06-06 | High - Enables cloud-native scaling |
| [ADR-007](ADR-007-PATTERN-STORAGE-ARCHITECTURE.md) | Security Pattern Storage Architecture | Implemented | 2025-06-09 | High - Performance & maintainability |
| [ADR-008](ADR-008-PATTERN-SERVING-API.md) | Pattern Serving API for IP Protection | Implemented | 2025-06-10 | Critical - $30B market enablement |
| [ADR-009](ADR-009-INFRASTRUCTURE-MIGRATION.md) | Infrastructure Migration to Centralized Repository | Implemented | 2025-06-19 | High - Enables scaling and operations |
| [ADR-010](ADR-010-FEATURE-FLAGS-SYSTEM.md) | Dynamic Feature Flags System | Implemented | 2025-06-16 | High - Enables rapid feature rollout |
| [ADR-011](ADR-011-CLAUDE-CODE-SDK-INTEGRATION.md) | Claude Code TypeScript SDK Integration | Implemented | 2025-06-22 | High - Deep context analysis capability |
| [ADR-012](ADR-012-IN-PLACE-VULNERABILITY-FIXES.md) | In-Place Vulnerability Fixes | Implemented | 2025-06-22 | High - Mergeable PRs |
| [ADR-013](ADR-013-IN-PLACE-EDITING-VALIDATION-FINDINGS.md) | In-Place Editing Validation Findings | Implemented | 2025-06-28 | Medium - Quality assurance |
| [ADR-014](ADR-014-ELIXIR-AST-SERVICE.md) | Elixir-Powered AST Analysis Service | Implemented | 2025-06-28 | Critical - Reduces false positives from 40% to <5% |
| [ADR-015](ADR-015-TIER-REMOVAL.md) | Pattern Tier Removal | Implemented | 2025-06-30 | High - Simplified architecture & 75% memory reduction |
| [ADR-016](ADR-016-AST-VALIDATION-ARCHITECTURE.md) | AST-Based Validation Architecture | Implemented | 2025-07-01 | Critical - 70-90% false positive reduction |
| [ADR-017](ADR-017-SERVICE-CONSOLIDATION-ARCHITECTURE.md) | Service Consolidation Architecture | Implemented | 2025-07-15 | High - 50% infrastructure cost reduction & unified platform |
| [ADR-018](ADR-018-AST-ANALYSIS-DEFERRED-DECISION.md) | Deferred AST Analysis Enhancement Decision | Accepted | 2025-07-17 | Medium - Data-driven architecture decisions |
| [ADR-019](ADR-019-STRUCTURED-PHASED-PROMPTING.md) | Structured Phased Prompting for Claude Code SDK | Implemented | 2025-08-03 | High - Ensures reliable file editing before JSON generation |
| [ADR-020](ADR-020-PHASE-DATA-PERSISTENCE.md) | Phase Data Persistence | Implemented | 2025-08-16 | Medium - Enables stateful multi-phase operations |
| [ADR-021](ADR-021-FALSE-POSITIVE-CACHING.md) | False Positive Caching | Implemented | 2025-08-16 | Medium - Performance optimization |
| [ADR-022](ADR-022-credential-auto-refresh-implementation.md) | Credential Auto-Refresh Implementation | Implemented | 2025-08-28 | Medium - Zero-downtime credential management |
| [ADR-023](ADR-023-claude-cli-credential-passing.md) | Claude CLI Credential Passing | Implemented | 2025-09-02 | High - Fixes credential vending integration |
| [ADR-024](ADR-024-AST-FALSE-POSITIVE-REDUCTION.md) | AST False Positive Reduction Strategy | Proposed | 2025-08-14 | High - Further reduces false positives |
| [ADR-025](ADR-025-DISTRIBUTED-RATE-LIMITING-WITH-MNESIA.md) | Distributed Rate Limiting with Mnesia | Implemented | 2025-09-10 | High - Eliminates race conditions in rate limiting |
| [ADR-026](ADR-026-CUSTOMER-MANAGEMENT-CONSOLIDATION.md) | Customer Management Consolidation | Implemented | 2025-09-11 | Critical - Unified authentication & -1,049 lines of code |
| [ADR-027](ADR-027-CENTRALIZED-API-AUTHENTICATION.md) | Centralized API Authentication | Implemented | 2025-09-17 | Critical - Fixes authentication recognition & standardizes API auth |
| [ADR-028](ADR-028-PRODUCTION-MIGRATION-FIX.md) | Production Database Migration Synchronization | Implemented | 2025-09-18 | Critical - Fixed production database schema issues |

## Related Documentation

- **[RFC Index](../RFCs/RFC-INDEX.md)**: Future architectural proposals and designs
- **[CLAUDE.md](../CLAUDE.md)**: Project guidelines and current implementation status
- **Implementation Status**: See individual component READMEs and status documents

## ADR Process

1. **Implementation Required**: Only convert RFCs to ADRs after implementation is verified in production
2. **Evidence-Based**: Each ADR must reference actual code implementation
3. **Business Impact**: Document business and technical consequences
4. **Status Updates**: Update status as decisions evolve or are superseded

## Archive

Superseded ADRs are moved to the `archived/` subdirectory but preserved for historical context.

### Draft/In Progress
- ADR-006: BEAM Clustering
- ADR-012: AST False Positive Reduction
- ADR-013: In-Place Editing Validation
- ADR-014: Elixir AST Service
- ADR-016: AST Validation Architecture
- ADR-017: Service Consolidation Architecture
- ADR-018: AST Analysis Deferred Decision
- ADR-020: Phase Data Persistence
- ADR-021: False Positive Caching

## Notes

- ADR-022 does not exist in git history
- ADR-011 and ADR-012 had conflicting versions (THREE-PHASE-ARCHITECTURE and IN-PLACE-VULNERABILITY-FIXES) that were resolved
- ADR-023 is the most recent addition documenting the Claude CLI credential passing fix

## Key Architectural Decisions

### Infrastructure
- Multi-repository organization (ADR-005)
- Infrastructure migration completed (ADR-009)
- Feature flags system in place (ADR-010)

### Security & AI
- Credential vending architecture (ADR-001)
- Security-first integration approach (ADR-003)
- Multi-model AI provider support (ADR-004)
- Claude Code SDK integration (ADR-011)

### Patterns & Validation
- Pattern storage and serving API (ADR-007, ADR-008)
- AST-based validation and false positive reduction (ADR-012, ADR-016, ADR-021)
- Structured phased prompting (ADR-019)