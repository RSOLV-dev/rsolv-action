# RSOLV RFC Index

This document tracks all Request for Comments (RFC) documents for the RSOLV project.

## RFC Process
1. **Draft** - Initial proposal, seeking feedback
2. **Review** - Under active discussion
3. **Approved** - Accepted for implementation
4. **Implemented** - Completed and converted to ADR
5. **Deprecated** - No longer relevant

## Related Documentation

- **[ADR Index](../ADRs/ADR-INDEX.md)**: Architecture decisions that have been implemented
- **Conversion Process**: Implemented RFCs are converted to ADRs for historical record

## RFC Directory Structure

All RFCs are now located in the `/RFCs` directory for better organization. This index provides a quick reference to all RFCs.

## Active RFCs

| RFC # | Title | Status | Created | Linear Issue |
|-------|-------|--------|---------|--------------|
| 001 | [Backup & Restore Strategy](RFC-001-BACKUP-RESTORE-PLAN.md) | Draft (Low Priority) | 2025-06-03 | [Infrastructure Project](https://linear.app/fitzgerald/project/infrastructure-backup-and-restore-strategy-9197282688b4) |
| 002 | [Staging Environment](RFC-002-STAGING-ENVIRONMENT.md) | Implemented | 2025-06-03 | [Infrastructure Project](https://linear.app/fitzgerald/project/infrastructure-staging-environment-4fcae2bbdefa) |
| 003 | [Learning Security System](RFC-003-LEARNING-SECURITY-SYSTEM.md) | Draft | 2025-06-03 | [FITZ-143](https://linear.app/fitzgerald/issue/FITZ-143) |
| 004 | [Webhook Infrastructure](RFC-004-WEBHOOK-INFRASTRUCTURE.md) | Implemented → [ADR-002](../ADRs/ADR-002-WEBHOOK-INFRASTRUCTURE.md) | 2025-06-03 | [FITZ-91](https://linear.app/fitzgerald/issue/FITZ-91) |
| 005 | [Feature Flags System](RFC-005-FEATURE-FLAGS.md) | Implemented → [ADR-010](../ADRs/ADR-010-FEATURE-FLAGS-SYSTEM.md) | 2025-06-03 | [FITZ-147](https://linear.app/fitzgerald/issue/FITZ-147) |
| 006 | [Multi-Model Security](RFC-006-MULTI-MODEL-SECURITY.md) | Draft | 2025-06-03 | [FITZ-148](https://linear.app/fitzgerald/issue/FITZ-148) |
| 007 | [AI Provider Expansion](RFC-007-AI-PROVIDER-EXPANSION.md) | Partially Implemented | 2025-06-03 | [FITZ-149](https://linear.app/fitzgerald/issue/FITZ-149) |
| 008 | [Pattern Serving API](RFC-008-PATTERN-SERVING-API.md) | Implemented → [ADR-008](../ADRs/ADR-008-PATTERN-SERVING-API.md) | 2025-06-03 | [FITZ-204](https://linear.app/fitzgerald/issue/FITZ-204) |
| 009 | [CI/CD Integration](RFC-009-CI-CD-INTEGRATION.md) | Draft | 2025-01-06 | [FITZ-172](https://linear.app/fitzgerald/issue/FITZ-172) |
| 010 | [Code Style Detection](RFC-010-CODE-STYLE-DETECTION.md) | Draft | 2025-01-06 | [FITZ-173](https://linear.app/fitzgerald/issue/FITZ-173) |
| 011 | [Test Generation](RFC-011-TEST-GENERATION.md) | Draft | 2025-01-06 | [FITZ-174](https://linear.app/fitzgerald/issue/FITZ-174) |
| 012 | [Credential Vending Architecture](RFC-012-CREDENTIAL-VENDING.md) | Implemented → [ADR-001](../ADRs/ADR-001-CREDENTIAL-VENDING-ARCHITECTURE.md) | 2025-06-04 | [FITZ-153](https://linear.app/fitzgerald/issue/FITZ-153) |
| 013 | [AI-Powered Deep Vulnerability Detection](RFC-013-AI-VULNERABILITY-DETECTION.md) | Draft | 2025-06-04 | [FITZ-180](https://linear.app/fitzgerald/issue/FITZ-180) |
| 014 | [Parallel AI Execution](RFC-014-PARALLEL-AI-EXECUTION.md) | Draft | 2025-06-06 | N/A |
| 015 | [Learning Security Business Model](RFC-015-LEARNING-SECURITY-BUSINESS-MODEL.md) | Draft | 2025-06-06 | N/A |
| 016 | [Elixir Nx Learning Engine](RFC-016-ELIXIR-NX-LEARNING-ENGINE.md) | Draft | 2025-06-06 | [FITZ-190](https://linear.app/fitzgerald/issue/FITZ-190) |
| 017 | [AI-Generated Code Security](RFC-017-AI-GENERATED-CODE-SECURITY.md) | Draft (Not Implemented) | 2025-06-07 | [FITZ-195](https://linear.app/fitzgerald/issue/FITZ-195) |
| 018 | [Blog Implementation Strategy](RFC-018-BLOG-IMPLEMENTATION-STRATEGY.md) | Implemented → [ADR-023](../ADRs/ADR-023-BLOG-IMPLEMENTATION.md) | 2025-06-07 | N/A |
| 019 | [Centralized Infrastructure Repository](RFC-019-CENTRALIZED-INFRASTRUCTURE.md) | Implemented → [ADR-009](../ADRs/ADR-009-INFRASTRUCTURE-MIGRATION.md) | 2025-06-16 | N/A |
| 020 | [Additional Rails Patterns](RFC-020-ADDITIONAL-RAILS-PATTERNS.md) | Draft | 2025-06-10 | N/A |
| 021 | [CakePHP Framework Coverage](RFC-021-CAKEPHP-FRAMEWORK-COVERAGE.md) | Draft | 2025-06-10 | N/A |
| 022 | [Pattern Categorization Strategy](RFC-022-PATTERN-CATEGORIZATION-STRATEGY.md) | Implemented | 2025-06-15 | High |
| 023 | Blog Implementation Strategy Variant (Analysis document - no separate file, see RFC-018) | Analysis | 2025-06-07 | N/A |
| 024 | [Strategic Comparison](RFC-024-STRATEGIC-COMPARISON.md) | Analysis | 2025-06-05 | N/A |
| 025 | [Slopsquatting Detection](RFC-025-SLOPSQUATTING-DETECTION.md) | Draft | 2025-01-10 | N/A |
| 026 | [CrowdSec Endpoint Protection](RFC-026-CROWDSEC-ENDPOINT-PROTECTION.md) | Draft | 2025-01-22 | TBD |
| 027 | [Terraform/IaC Security Test Generation](RFC-027-TERRAFORM-IAC-SECURITY.md) | Draft | 2025-06-24 | N/A |
| 028 | [Fix Validation Integration](RFC-028-FIX-VALIDATION-INTEGRATION.md) | Implemented | 2025-06-24 | N/A |
| 029 | [Multi-Language AST Parsing](RFC-029-MULTI-LANGUAGE-AST-PARSING.md) | Implemented | 2025-06-12 | Medium |
| 030 | [Universal Test Framework Detection](RFC-030-UNIVERSAL-TEST-FRAMEWORK-DETECTION.md) | Draft | 2025-06-25 | N/A |
| 031 | [Elixir AST Analysis Service](RFC-031-ELIXIR-AST-ANALYSIS-SERVICE.md) | Implemented → [ADR-014](../ADRs/ADR-014-ELIXIR-AST-SERVICE.md) | 2025-06-25 | N/A |
| 032 | [Pattern API JSON Migration](RFC-032-PATTERN-API-JSON-MIGRATION.md) | Implemented | 2025-06-28 | N/A |
| 033 | [True Git-Based Editing Implementation](RFC-033-TRUE-GIT-BASED-EDITING.md) | Draft | 2025-06-28 | N/A |
| 034 | [Framework Detection](RFC-034-FRAMEWORK-DETECTION.md) | Draft | 2025-06-29 | N/A |
| 035 | [AST Interpreter Enhancement](RFC-035-AST-INTERPRETER-ENHANCEMENT.md) | Partially Implemented (Basic Only) | 2025-06-29 | N/A |
| 036 | [Server-side AST Validation](RFC-036-SERVER-SIDE-AST-VALIDATION.md) | Implemented → [ADR-016](../ADRs/ADR-016-AST-VALIDATION-ARCHITECTURE.md) | 2025-07-01 | N/A |
| 037 | [Service Consolidation](RFC-037-SERVICE-CONSOLIDATION.md) | Completed → [ADR-017](../ADRs/ADR-017-SERVICE-CONSOLIDATION-ARCHITECTURE.md) | 2025-07-01 | N/A |
| 038 | [Distributed AST Caching with Mnesia](RFC-038-DISTRIBUTED-CACHING-MNESIA.md) | Proposed | 2025-01-30 | N/A |
| 039 | [Audit Log Exposure and Observability](RFC-039-AUDIT-LOG-EXPOSURE.md) | Proposed | 2025-06-27 | N/A |
| 040 | [CLI Test Validation Fix](RFC-040-CLI-TEST-VALIDATION-FIX.md) | Implemented | 2025-08-05 | N/A |
| 041 | [Three-Phase Architecture](RFC-041-THREE-PHASE-ARCHITECTURE.md) | Implemented | 2025-08-06 | N/A |
| 042 | [Phase Data Platform API](RFC-042-AST-FALSE-POSITIVE-REDUCTION.md) | Draft | 2025-08-06 | N/A |
| 043 | [Enhanced Three-Phase Validation](RFC-043-ENHANCED-THREE-PHASE-VALIDATION.md) | Implemented | 2025-08-08 | N/A |
| 044 | [Phase Data Persistence Implementation](RFC-044-PHASE-DATA-PERSISTENCE.md) | In Development → [ADR-020](../ADRs/ADR-020-PHASE-DATA-PERSISTENCE.md) | 2025-08-15 | N/A |
| 045 | [False Positive Caching](RFC-045-FALSE-POSITIVE-CACHING.md) | Implemented → [ADR-021](../ADRs/ADR-021-FALSE-POSITIVE-CACHING.md) | 2025-08-20 | N/A |
| 046 | [False Positive Caching TDD](RFC-046-FALSE-POSITIVE-CACHING-TDD.md) | Implemented | 2025-08-22 | N/A |
| 047 | [Vendor Library Detection](RFC-047-vendor-library-detection.md) | Implemented (Deployed) | 2025-08-25 | N/A |
| 048 | [API Test Mode](RFC-048-API-TEST-MODE.md) | Draft | 2025-08-28 | N/A |
| 049 | [Customer Management Consolidation](RFC-049-CUSTOMER-MANAGEMENT-CONSOLIDATION.md) | Implemented (needs ADR) | 2025-09-03 | N/A |
| 050 | [Self-Improving Security Platform](RFC-050-SELF-IMPROVING-SECURITY-PLATFORM.md) | Draft (RFC-014 variant) | 2025-06-06 | [FITZ-188](https://linear.app/fitzgerald/issue/FITZ-188) |
| 051 | [Strategic Deep Analysis](RFC-051-STRATEGIC-DEEP-ANALYSIS.md) | Analysis (RFC-014 variant) | 2025-06-06 | N/A |
| 052 | [Analysis: Parallel AI Execution](RFC-052-ANALYSIS-PARALLEL-AI-EXECUTION.md) | Analysis (RFC-014 variant) | 2025-06-06 | N/A |
| 053 | [Urgent IP Protection](RFC-053-URGENT-IP-PROTECTION.md) | Implemented via RFC-008 (RFC-018 variant) | 2025-06-07 | [FITZ-195](https://linear.app/fitzgerald/issue/FITZ-195) |
| 054 | [Distributed Rate Limiter](RFC-054-DISTRIBUTED-RATE-LIMITER.md) | Implemented (needs ADR) | 2025-09-05 | N/A |
| 055 | [Customer Schema Consolidation](RFC-055-CUSTOMER-SCHEMA-CONSOLIDATION.md) | Implemented (needs ADR) | 2025-09-09 | N/A |
| 056 | [Admin UI for Customer Management](RFC-056-ADMIN-UI-CUSTOMER-MANAGEMENT.md) | Implemented (needs ADR) | 2025-09-10 | N/A |
| 057 | [Fix Credential Vending](RFC-057-FIX-CREDENTIAL-VENDING.md) | Draft | 2025-09-18 | N/A |
| 058 | [Validation Branch Persistence](RFC-058-VALIDATION-BRANCH-PERSISTENCE.md) | Implemented → [ADR-025](../ADRs/ADR-025-VALIDATION-BRANCH-PERSISTENCE.md) | 2025-09-18 | N/A |
| 059 | [Local Testing with Act](RFC-059-act-local-testing.md) | Approved (Note: RFC-059-VALIDATION-TESTING-STRATEGY.md also exists) | 2025-01-24 | N/A |
| 060 | [Executable Validation Test Integration](RFC-060-ENHANCED-VALIDATION-TEST-PERSISTENCE.md) | ✅ Complete (v3.7.54 + Amendment 001) → [ADR-031](../ADRs/ADR-031-AST-TEST-INTEGRATION.md) | 2025-09-30 | N/A |
| 060-A1 | [Backend-Led Test Integration](RFC-060-AMENDMENT-001-TEST-INTEGRATION.md) | ✅ Complete (Deployed 2025-10-15) → [ADR-031](../ADRs/ADR-031-AST-TEST-INTEGRATION.md) | 2025-10-12 | N/A |
| 061 | [Claude CLI Retry Reliability](RFC-061-CLAUDE-RETRY-RELIABILITY.md) | Draft | 2025-09-30 | N/A |
| 062 | [CI Integration Testing Infrastructure](RFC-062-CI-INTEGRATION-TESTING.md) | Draft | 2025-10-06 | N/A |
| 063 | [API Key Caching with Mnesia](RFC-063-API-KEY-CACHING.md) | Draft | 2025-10-07 | N/A |
| 064 | [Billing & Provisioning Master Plan](RFC-064-BILLING-PROVISIONING-MASTER-PLAN.md) | Draft | 2025-10-12 | N/A |
| 065 | [Automated Customer Provisioning](RFC-065-AUTOMATED-CUSTOMER-PROVISIONING.md) | Draft | 2025-10-12 | N/A |
| 066 | [Stripe Billing Integration](RFC-066-STRIPE-BILLING-INTEGRATION.md) | Draft | 2025-10-12 | N/A |
| 067 | [GitHub Marketplace Publishing](RFC-067-GITHUB-MARKETPLACE-PUBLISHING.md) | Draft | 2025-10-12 | N/A |
| 068 | [Billing Testing Infrastructure](RFC-068-BILLING-TESTING-INFRASTRUCTURE.md) | Draft | 2025-10-12 | N/A |
| 069 | [Integration Week Plan](RFC-069-INTEGRATION-WEEK.md) | Draft | 2025-10-12 | N/A |
| 070 | [Customer Authentication](RFC-070-CUSTOMER-AUTHENTICATION.md) | Draft (Future Work after RFC-064) | 2025-10-16 | N/A |
| 071 | [Customer Portal UI](RFC-071-CUSTOMER-PORTAL-UI.md) | Draft (Future Work after RFC-070) | 2025-10-16 | N/A |
| 072 | [OAuth Integration (GitHub/GitLab)](RFC-072-OAUTH-INTEGRATION.md) | Draft (Future Work - post RFC-064) | 2025-10-20 | N/A |
| 073 | ~~Multi-User Account Management~~ | Removed (premature - multi-user way down the line) | 2025-10-20 | N/A |
| 074 | [CLI Provisioning Tool](RFC-074-CLI-PROVISIONING.md) | Draft (Future Work - post RFC-065) | 2025-10-20 | N/A |
| 075 | [Signup Webhook Events](RFC-075-SIGNUP-WEBHOOKS.md) | Draft (Future Work - post RFC-065) | 2025-10-20 | N/A |
| 076 | [GitHub App for Workflow Installation](RFC-076-GITHUB-APP-WORKFLOW-INSTALL.md) | Draft (Future Work - post RFC-065) | 2025-10-20 | N/A |

## RFC Implementation Tracking

### Supporting Documents
Many RFCs have additional tracking documents:
- **RFC-031**: Multiple phases documented (API-CONTRACT, CHECKPOINT-PHASE-2, CHECKPOINT-PHASE-3, PHASE-1-2-PROGRESS, PHASE-1-PROGRESS, PHASE4-REVIEW, TECHNICAL-REVIEW)
- **RFC-032**: Implementation tracking (IMPLEMENTATION-SUMMARY, PHASE-1-3-RESULTS)
- **RFC-036**: Implementation status tracking (IMPLEMENTATION-STATUS)
- **RFC-037**: Final status and implementation tracking (FINAL-STATUS-SUMMARY, IMPLEMENTATION-STATUS)

### Implementation Status Directories
RFCs with extensive implementation tracking:
- **RFC-008** (Pattern Serving API): `RFC-008-implementation-status/` - Contains all status reports, backup verification, and completion summaries
- **RFC-031** (Elixir AST Analysis Service): `RFC-031-implementation-status/` - Contains phase summaries and implementation plans
- **RFC-036** (Server-side AST Validation): `RFC-036-implementation-status/` - Contains implementation status and tracking

## Recently Converted to ADRs

The following RFCs have been implemented and converted to Architecture Decision Records:
- RFC-002 (Staging Environment) → Implemented
- RFC-004 (Webhook Infrastructure) → [ADR-002](../ADRs/ADR-002-WEBHOOK-INFRASTRUCTURE.md)
- RFC-005 (Feature Flags System) → [ADR-010](../ADRs/ADR-010-FEATURE-FLAGS-SYSTEM.md)
- RFC-008 (Pattern Serving API) → [ADR-008](../ADRs/ADR-008-PATTERN-SERVING-API.md)
- RFC-012 (Credential Vending) → [ADR-001](../ADRs/ADR-001-CREDENTIAL-VENDING-ARCHITECTURE.md)
- RFC-019 (Centralized Infrastructure) → [ADR-009](../ADRs/ADR-009-INFRASTRUCTURE-MIGRATION.md)
- RFC-031 (Elixir AST Analysis Service) → [ADR-014](../ADRs/ADR-014-ELIXIR-AST-SERVICE.md)
- RFC-036 (Server-side AST Validation) → [ADR-016](../ADRs/ADR-016-AST-VALIDATION-ARCHITECTURE.md)
- RFC-037 (Service Consolidation) → [ADR-017](../ADRs/ADR-017-SERVICE-CONSOLIDATION-ARCHITECTURE.md)
- RFC-044 (Phase Data Persistence) → [ADR-020](../ADRs/ADR-020-PHASE-DATA-PERSISTENCE.md)
- RFC-045 (False Positive Caching) → [ADR-021](../ADRs/ADR-021-FALSE-POSITIVE-CACHING.md)

Additional ADRs created from implemented designs:
- Security-First Integration → [ADR-003](../ADRs/ADR-003-SECURITY-FIRST-INTEGRATION.md)
- Multi-Model AI Provider Strategy → [ADR-004](../ADRs/ADR-004-MULTI-MODEL-AI-PROVIDER.md)
- Multi-Repository Organization → [ADR-005](../ADRs/ADR-005-MULTI-REPOSITORY-ORGANIZATION.md)
- Claude Code TypeScript SDK Integration → [ADR-011](../ADRs/ADR-011-CLAUDE-CODE-SDK-INTEGRATION.md)
- In-Place Vulnerability Fixes → [ADR-012](../ADRs/ADR-012-IN-PLACE-VULNERABILITY-FIXES.md)
- In-Place Editing Validation → [ADR-013](../ADRs/ADR-013-IN-PLACE-EDITING-VALIDATION-FINDINGS.md)

## RFC Template

```markdown
# RFC: [Title]

**RFC Number**: XXX  
**Title**: [Full Title]  
**Author**: [Team/Person]  
**Status**: Draft  
**Created**: [Date]  

## Summary
[1-2 paragraph overview]

## Motivation
[Why do we need this?]

## Proposed Solution
[Detailed technical approach]

## Implementation Plan
[Phases and timeline]

## Alternatives Considered
[Other approaches and why rejected]

## Open Questions
[Unresolved issues]

## References
[Related documents]
```

## Next Steps

1. **Immediate**: Complete RFC-049 (Customer Management Consolidation) implementation
2. **Soon**: Review and update draft RFCs for relevance
3. **Future**: Archive deprecated RFCs and update Linear issues

## RFC Locations

All RFCs should be:
- In `/RFCs` directory with `RFC-NNN-` prefix
- Linked in this index
- Have corresponding Linear issue/project (where applicable)
- Follow the standard template

## Known Issues and Recommendations (Updated 2025-10-08)

### Cleanup Completed (2025-10-08)

✅ **Removed duplicate files:**
- Deleted `RFC-032-DISTRIBUTED-CACHING-MNESIA.md` (duplicate of RFC-038)
- Deleted `RFC-033-AUDIT-LOG-EXPOSURE.md` (duplicate of RFC-039)

### Remaining Actions Required

1. **Missing ADRs for Implemented RFCs**
   - RFC-022 (Pattern Categorization) - needs ADR
   - RFC-029 (Multi-Language AST) - verify if covered by ADR-014 or create new ADR
   - RFC-047 (Vendor Library Detection) - needs ADR
   - RFC-049 (Customer Management) - needs ADR
   - RFC-054 (Distributed Rate Limiter) - needs ADR
   - RFC-055 (Customer Schema Consolidation) - needs ADR
   - RFC-056 (Admin UI Customer Management) - needs ADR

### Documentation Notes

- **RFC-023**: Was a duplicate of RFC-018 (deleted in commit 9c1e141), index entry retained for historical tracking
- **RFC-059**: Has two valid files (act-local-testing and validation-testing-strategy) covering related topics
- **RFC-060**: Has backup file RFC-060-BACKUP-1759329597.md

## Notes

- RFC numbering conflicts resolved by renumbering variants (RFC-050 through RFC-053)
- Multiple supporting documents for RFC-031, RFC-032, RFC-033, RFC-036, RFC-037 represent different phases or aspects
- Total of 63 unique RFCs plus supporting documentation
- Last validated: 2025-10-08