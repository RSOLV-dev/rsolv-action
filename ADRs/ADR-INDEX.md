# ADR Index - Architecture Decision Records

**Last Updated**: 2025-09-03  
**Total ADRs**: 22

## All ADRs

| Number | Title | Status | Created |
|--------|-------|--------|---------|
| [ADR-001](ADR-001-CREDENTIAL-VENDING-ARCHITECTURE.md) | Credential Vending Architecture | Implemented | Historical |
| [ADR-002](ADR-002-WEBHOOK-INFRASTRUCTURE.md) | Webhook Infrastructure | Implemented | Historical |
| [ADR-003](ADR-003-SECURITY-FIRST-INTEGRATION.md) | Security First Integration | Implemented | Historical |
| [ADR-004](ADR-004-MULTI-MODEL-AI-PROVIDER.md) | Multi-Model AI Provider | Implemented | Historical |
| [ADR-005](ADR-005-MULTI-REPOSITORY-ORGANIZATION.md) | Multi-Repository Organization | Implemented | Historical |
| [ADR-006](ADR-006-BEAM-CLUSTERING.md) | BEAM Clustering | Draft | Historical |
| [ADR-007](ADR-007-PATTERN-STORAGE-ARCHITECTURE.md) | Pattern Storage Architecture | Implemented | Historical |
| [ADR-008](ADR-008-PATTERN-SERVING-API.md) | Pattern Serving API | Implemented | Historical |
| [ADR-009](ADR-009-INFRASTRUCTURE-MIGRATION.md) | Infrastructure Migration | Implemented | Historical |
| [ADR-010](ADR-010-FEATURE-FLAGS-SYSTEM.md) | Feature Flags System | Implemented | Historical |
| [ADR-011](ADR-011-CLAUDE-CODE-SDK-INTEGRATION.md) | Claude Code SDK Integration | Implemented | Historical |
| [ADR-012](ADR-012-AST-FALSE-POSITIVE-REDUCTION.md) | AST False Positive Reduction | Draft | Historical |
| [ADR-013](ADR-013-IN-PLACE-EDITING-VALIDATION-FINDINGS.md) | In-Place Editing Validation Findings | Draft | Historical |
| [ADR-014](ADR-014-ELIXIR-AST-SERVICE.md) | Elixir AST Service | Draft | Historical |
| [ADR-015](ADR-015-TIER-REMOVAL.md) | Tier Removal | Implemented | Historical |
| [ADR-016](ADR-016-AST-VALIDATION-ARCHITECTURE.md) | AST Validation Architecture | Draft | Historical |
| [ADR-017](ADR-017-SERVICE-CONSOLIDATION-ARCHITECTURE.md) | Service Consolidation Architecture | Draft | Historical |
| [ADR-018](ADR-018-AST-ANALYSIS-DEFERRED-DECISION.md) | AST Analysis Deferred Decision | Draft | Historical |
| [ADR-019](ADR-019-STRUCTURED-PHASED-PROMPTING.md) | Structured Phased Prompting | Implemented | Historical |
| [ADR-020](ADR-020-PHASE-DATA-PERSISTENCE.md) | Phase Data Persistence | Draft | Historical |
| [ADR-021](ADR-021-FALSE-POSITIVE-CACHING.md) | False Positive Caching | Draft | Historical |
| ADR-022 | (Not found in git history) | N/A | N/A |
| **[ADR-023](ADR-023-claude-cli-credential-passing.md)** | **Claude CLI Credential Passing** | **Implemented** | **2025-09-02** |

## Categories

### Implemented
- ADR-001: Credential Vending
- ADR-002: Webhook Infrastructure
- ADR-003: Security First Integration
- ADR-004: Multi-Model AI Provider
- ADR-005: Multi-Repository Organization
- ADR-007: Pattern Storage Architecture
- ADR-008: Pattern Serving API
- ADR-009: Infrastructure Migration
- ADR-010: Feature Flags System
- ADR-011: Claude Code SDK Integration
- ADR-015: Tier Removal
- ADR-019: Structured Phased Prompting
- ADR-023: Claude CLI Credential Passing

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