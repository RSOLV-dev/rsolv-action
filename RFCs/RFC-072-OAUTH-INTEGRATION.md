# RFC-072: OAuth Integration (GitHub/GitLab)

**Status**: Draft (Future Work - post RFC-064)
**Created**: 2025-10-20
**Timeline**: TBD
**Dependencies**: RFC-065 (Automated Customer Provisioning)

## Related RFCs

**Depends on:**
- RFC-065 (Automated Customer Provisioning) - Must complete first

**Enables:**
- Simpler signup flow with verified email
- Auto-filled profile data
- GitHub/GitLab repository access

## Summary

Implement OAuth authentication for GitHub and GitLab to streamline customer signup and enable verified email addresses with auto-filled profile information.

## Problem

Current email-based signup requires:
- Manual email entry (prone to typos)
- Email verification step
- Separate GitHub authentication for repository access
- No verified identity

## Proposed Solution

### GitHub OAuth
- OAuth flow for signup
- Auto-fill: name, email, avatar from GitHub profile
- Verified email benefit (GitHub-verified emails trusted)
- Repository access token for workflow installation

### GitLab OAuth
- Similar flow for GitLab users
- Support GitLab.com and self-hosted instances
- Auto-fill profile data

## Benefits

- **Faster signup** - One-click with GitHub/GitLab
- **Verified identity** - Trust GitHub/GitLab verification
- **Better UX** - No manual email entry
- **Repository access** - Can install workflows programmatically

## Technical Approach

**To be determined:**
- ueberauth library for Elixir OAuth
- Token storage strategy
- Privacy considerations (what data we store)
- Fallback to email signup (always available)

## Next Steps

1. Complete RFC-065 production deployment
2. Gather user feedback on email signup friction
3. Design OAuth flow and UX
4. Create detailed implementation plan
