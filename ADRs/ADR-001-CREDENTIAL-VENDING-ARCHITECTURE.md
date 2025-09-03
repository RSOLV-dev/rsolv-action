# ADR-001: Credential Vending Architecture

**Status**: Implemented  
**Date**: 2025-06-03  
**Authors**: Infrastructure Team  
**Supersedes**: RFC-012

## Context

RSOLV initially required customers to obtain and manage API keys from multiple AI providers (Anthropic, OpenAI, etc.), which created significant friction:

- **Complex Onboarding**: Customers needed to create accounts with 3-4 AI providers
- **Security Risk**: Multiple API keys stored in GitHub Secrets across repositories  
- **Key Management**: Customers responsible for rotation, monitoring, and security
- **Provider Coupling**: Changes required customer reconfiguration
- **Time Investment**: 30+ minutes to set up vs. 5 minutes with single key

The business requirement was to reduce onboarding friction while maintaining security and enabling rapid AI provider changes without customer impact.

## Decision

We implemented a **credential vending service** where customers exchange their single RSOLV API key for temporary, scoped AI provider credentials:

### Architecture Components

1. **RSOLVCredentialManager** (Client-side)
   - Located: `RSOLV-action/src/credentials/manager.ts`
   - Exchanges RSOLV API key for AI credentials
   - Caches credentials with 1-hour TTL
   - Automatic refresh before expiry

2. **Credential Controller** (Server-side)  
   - Located: `RSOLV-api/lib/rsolv_web/controllers/credential_controller.ex`
   - Validates customer API keys
   - Retrieves and encrypts AI provider credentials
   - Tracks usage for billing and audit

3. **Security Features**
   - 1-hour credential TTL (configurable)
   - TLS + additional encryption layer
   - Complete audit trail of all exchanges
   - Rate limiting per customer
   - No plaintext key storage

### API Design

```
POST /api/v1/credentials/exchange
{
  "provider": "anthropic"
}
→ Returns encrypted temporary credentials

POST /api/v1/credentials/refresh  
→ Refreshes expiring credentials

POST /api/v1/credentials/report_usage
→ Reports usage metrics for billing
```

### Customer Experience

- **Before**: Configure ANTHROPIC_API_KEY, OPENAI_API_KEY, OPENROUTER_API_KEY
- **After**: Configure single RSOLV_API_KEY
- **Onboarding**: Reduced from 30+ minutes to 5 minutes

## Consequences

### Positive

- **Simplified Customer Experience**: Single API key management
- **Enhanced Security**: Customers never handle AI provider keys directly
- **Business Agility**: Change AI providers without customer reconfiguration  
- **Cost Management**: Consolidated billing and usage tracking
- **Competitive Advantage**: Significantly easier onboarding than competitors
- **Audit Compliance**: Complete trail of credential usage

### Trade-offs

- **Dependency**: Customers depend on RSOLV infrastructure for AI access
- **Latency**: Additional network hop for credential exchange (mitigated by caching)
- **Complexity**: More infrastructure to maintain and secure
- **Cost**: Higher operational overhead vs. direct customer billing

### Business Impact

- **Customer Acquisition**: 6x faster onboarding (30 min → 5 min)
- **Support Reduction**: Eliminated 80% of "API key not working" tickets  
- **Revenue Enablement**: Simplified billing and usage tracking
- **Market Position**: Only platform offering single-key onboarding

## Implementation Evidence

**Production Deployment**: https://api.rsolv.dev/api/v1/credentials/exchange

**Code Locations**:
- Client: `RSOLV-action/src/credentials/manager.ts`
- Server: `RSOLV-api/lib/rsolv_web/controllers/credential_controller.ex`
- Tests: `RSOLV-action/src/__tests__/credentials/manager.test.ts`

**Migration Strategy**: Dual support for both direct keys and vended credentials during transition period.

## Related Decisions

- **ADR-002**: Webhook Infrastructure (depends on customer identification)
- **ADR-004**: Multi-Model AI Provider (enabled by credential abstraction)

## References

- Original RFC: `RFCs/RFC-012-CREDENTIAL-VENDING.md`
- Implementation Guide: `RSOLV-docs/implementation/credential-vending.md`
- Security Audit: `security/credential-vending-audit.md`