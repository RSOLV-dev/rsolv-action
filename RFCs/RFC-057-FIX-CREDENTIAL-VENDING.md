# RFC-057: Fix Credential Vending Implementation

**Title**: Properly Mount AI Provider Secrets in K8s Deployments
**Author**: Infrastructure Team
**Status**: Draft
**Created**: 2025-09-17
**Linear Issue**: N/A

## Summary

The credential vending system documented in RFC-012 and ADR-001 was not working because the AI provider API keys stored in Kubernetes secrets were not being mounted as environment variables in the deployment configurations. This RFC documents the fix to properly expose these secrets to the RSOLV platform application.

## Problem

The credential exchange endpoint (`/api/v1/credentials/exchange`) was returning 500 errors with "Internal server error". Investigation revealed:

1. **K8s secrets exist**: The secrets `anthropic-api-key`, `openai-api-key`, and `openrouter-api-key` are properly stored in the `rsolv-secrets` Secret object
2. **Application expects env vars**: The application runtime config expects these as `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, etc.
3. **Missing mount**: The deployment configurations were not mounting these secrets as environment variables
4. **Result**: The application was returning mock keys instead of real credentials

## Solution

Update the Kubernetes deployment patches to properly mount the AI provider secrets as environment variables:

### Production Deployment (`services/unified/overlays/production/deployment-patch.yaml`)

```yaml
- name: ANTHROPIC_API_KEY
  valueFrom:
    secretKeyRef:
      name: rsolv-secrets
      key: anthropic-api-key
- name: OPENAI_API_KEY
  valueFrom:
    secretKeyRef:
      name: rsolv-secrets
      key: openai-api-key
- name: OPENROUTER_API_KEY
  valueFrom:
    secretKeyRef:
      name: rsolv-secrets
      key: openrouter-api-key
```

### Staging Deployment (`services/unified/overlays/staging/deployment-patch.yaml`)

Same configuration as production.

## Implementation Checklist

- [x] Update production deployment patch
- [x] Update staging deployment patch
- [ ] Deploy to staging environment
- [ ] Test credential exchange on staging
- [ ] Deploy to production environment
- [ ] Verify credential exchange on production
- [ ] Update monitoring to track credential vending success rate

## Testing

1. **Manual Test**:
```bash
curl -X POST "https://api.rsolv.dev/api/v1/credentials/exchange" \
  -H "x-api-key: $RSOLV_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"providers": ["anthropic"], "ttl_minutes": 60}'
```

Should return actual encrypted credentials, not mock keys.

2. **GitHub Action Test**:
- Run RSOLV workflow on NodeGoat demo repository
- Verify PRs are created successfully without credential errors

## Impact

- **Immediate**: Fixes credential vending for all customers
- **Long-term**: Enables the single-API-key onboarding experience
- **Security**: No security impact; improves security by properly vending temporary credentials

## Alternatives Considered

1. **Store keys in application code**: Rejected - security risk
2. **Use ConfigMap**: Rejected - secrets should use Secret objects
3. **Mount as volume**: Rejected - environment variables are simpler for this use case

## References

- ADR-001: Credential Vending Architecture
- RFC-012: Credential Vending System
- Issue: Credential exchange returning 500 errors