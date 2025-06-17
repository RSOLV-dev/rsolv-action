# RSOLV API RFCs (Request for Comments)

This directory contains RFCs for proposed changes, features, and architectural decisions for the RSOLV API.

## RFC Process

1. **Draft**: Initial proposal for discussion
2. **Review**: Under review by team/stakeholders  
3. **Approved**: Accepted for implementation
4. **Implemented**: Feature has been built
5. **Rejected**: Not moving forward

## Active RFCs

| RFC | Title | Status | Created | Author |
|-----|-------|--------|---------|--------|
| [RFC-008](./RFC-008-PATTERN-SERVING-API.md) | Pattern Serving API | Implemented | 2025-01-03 | Security Team |
| [RFC-013](./RFC-013-AI-VULNERABILITY-DETECTION.md) | AI Vulnerability Detection | Draft | 2025-01-10 | AI Team |
| [RFC-017](./RFC-017-AI-GENERATED-CODE-SECURITY.md) | AI Generated Code Security | Approved | 2025-01-14 | Strategy Team |
| [RFC-019](./RFC-019-ADDITIONAL-RAILS-PATTERNS.md) | Additional Rails Security Patterns | Draft | 2025-01-16 | Security Team |
| [RFC-020](./RFC-020-CAKEPHP-FRAMEWORK-COVERAGE.md) | CakePHP Framework Vulnerability Coverage | Draft | 2025-06-16 | Security Team |

## RFC Template

When creating a new RFC, use this structure:

```markdown
# RFC-XXX: Title

**RFC ID**: RFC-XXX  
**Title**: Brief descriptive title  
**Author**: Your name/team  
**Status**: Draft  
**Created**: YYYY-MM-DD  
**Updated**: YYYY-MM-DD  

## Abstract
Brief summary of the proposal (2-3 sentences)

## Motivation
Why is this needed? What problem does it solve?

## Detailed Design
Technical details, implementation approach, examples

## Benefits
What are the advantages of this approach?

## Risks and Mitigation
What could go wrong? How do we handle it?

## Implementation Plan
Step-by-step plan to implement

## Success Metrics
How do we measure success?

## Alternatives Considered
What other approaches were evaluated?

## References
Links to relevant docs, research, prior art

## Decision
Current status and next steps
```

## Naming Convention

RFCs should be numbered sequentially (RFC-001, RFC-002, etc.) and have descriptive titles that clearly indicate their purpose.

## Categories

- **Architecture**: System design changes
- **Security**: New security patterns or features
- **API**: Public API changes
- **Performance**: Optimization proposals
- **Process**: Development workflow changes