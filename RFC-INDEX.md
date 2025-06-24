# RFC Index - RSOLV Project

This document tracks all Request for Comments (RFC) documents in the RSOLV project. RFCs are used to document architectural decisions, design proposals, and significant feature implementations.

## Active RFCs

| RFC Number | Title | Status | Created | Author |
|------------|-------|--------|---------|---------|
| [RFC-019](./RFCs/RFC-019-TERRAFORM-IAC-SECURITY.md) | Terraform/IaC Security Test Generation | Draft | 2025-06-24 | RSOLV Team |
| [RFC-020](./RFCs/RFC-020-FIX-VALIDATION-INTEGRATION.md) | Fix Validation Integration | Draft | 2025-06-24 | RSOLV Team |
| [RFC-021](./RFCs/RFC-021-MULTI-LANGUAGE-AST-PARSING.md) | Multi-Language AST Parsing Architecture | Draft | 2025-06-24 | RSOLV Team |
| [RFC-022](./RFCs/RFC-022-UNIVERSAL-TEST-FRAMEWORK-DETECTION.md) | Universal Test Framework Detection | Draft | 2025-06-21 | RSOLV Team |
| [RFC-023](./RFCs/RFC-023-ELIXIR-AST-ANALYSIS-SERVICE.md) | Elixir-Powered AST Analysis Service | Draft | 2025-06-24 | RSOLV Team |

## Planned RFCs

| RFC Number | Title | Status | Description |
|------------|-------|--------|-------------|
| RFC-024 | (Next Available) | - | - |

## Historical RFCs

| RFC Number | Title | Status | Notes |
|------------|-------|--------|-------|
| RFC-003 | (Unknown) | Referenced | Referenced in codebase but document not found |
| RFC-008 | Pattern Serving API | Implemented | Core pattern serving architecture (referenced extensively in code) |

## RFC Numbering Issue

**Note**: RFC-021 was accidentally assigned to two different RFCs:
- Multi-Language AST Parsing Architecture (created 2025-06-24)
- Universal Test Framework Detection (created 2025-06-21)

The Universal Test Framework Detection RFC should be renumbered to RFC-022 to resolve this conflict.

## RFC Process

1. **Draft**: Initial proposal and design
2. **Review**: Under review by team
3. **Accepted**: Approved for implementation
4. **Implemented**: Feature has been built
5. **Deprecated**: No longer relevant or superseded

## Creating New RFCs

When creating a new RFC:
1. Check this index for the next available number
2. Use the template: `RFC-XXX-DESCRIPTIVE-NAME.md`
3. Place in the `/RFCs` directory
4. Update this index immediately
5. Include standard RFC headers (Status, Created, Author, Summary)

## RFC Categories

### Architecture & Design
- RFC-020: Fix Validation Integration
- RFC-021: Multi-Language AST Parsing Architecture
- RFC-022: Universal Test Framework Detection
- RFC-023: Elixir-Powered AST Analysis Service

### Security Features
- RFC-008: Pattern Serving API (implemented)
- RFC-019: Terraform/IaC Security Test Generation

### Integration & APIs
- RFC-008: Pattern Serving API

## Next Steps

1. ~~Rename `RFC-021-UNIVERSAL-TEST-FRAMEWORK-DETECTION.md` to `RFC-022-UNIVERSAL-TEST-FRAMEWORK-DETECTION.md`~~ ✅
2. ~~Create RFC-019 for Terraform/IaC Security Coverage (Phase 7)~~ ✅
3. Document RFC-003 if still relevant
4. Consider documenting RFC-008 formally if not already present in git history
5. Implement RFC-023 after completing current vulnerability detection improvements
6. Implement RFC-019 patterns and test generation for IaC