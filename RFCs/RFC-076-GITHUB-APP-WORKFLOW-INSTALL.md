# RFC-076: GitHub App for One-Click Workflow Installation

**Status**: Draft (Future Work - post RFC-064)
**Created**: 2025-10-20
**Timeline**: TBD (Complex - estimate 3-4 weeks)
**Dependencies**: RFC-065 (Automated Customer Provisioning)

## Related RFCs

**Depends on:**
- RFC-065 (Automated Customer Provisioning) - Customer accounts required

**Alternative to:**
- Manual workflow file copy/paste (current approach)
- CLI tool installation (RFC-074)

**Enables:**
- True one-click setup from dashboard
- No manual file editing
- Programmatic workflow updates

## Summary

Build a GitHub App (separate from RSOLV Action) that can programmatically create workflow files in customer repositories via GitHub API, eliminating manual copy/paste.

## Problem

Current workflow installation:
1. Customer downloads `.github/workflows/rsolv.yml` file
2. Customer creates `.github/workflows/` directory (if needed)
3. Customer pastes file contents manually
4. Customer commits to repository

**Still requires manual file editing** - not ideal for modern SaaS UX.

## Proposed Solution

### GitHub App
- **Not a GitHub Action** (separate entity)
- OAuth installation flow
- Permissions: Read/write workflows, read repository metadata
- Can create files via GitHub Contents API

### One-Click Flow
1. Customer clicks "Install Workflow" in dashboard
2. OAuth to GitHub, select repository
3. GitHub App creates `.github/workflows/rsolv.yml` automatically
4. Optionally creates PR with workflow (customer reviews/merges)
5. Done - workflow installed

### API Access
- Create/update workflow files
- Detect framework for workflow customization
- Keep workflows updated (future: auto-update feature)

## Benefits

- **True one-click** - No file editing required
- **Better UX** - Matches modern SaaS expectations
- **Auto-updates** - Can push workflow improvements
- **Less support** - Fewer setup issues

## Challenges

- **Complex OAuth flow** - Installation, permissions, token management
- **GitHub App overhead** - Separate app to maintain
- **Security considerations** - Write access to repositories
- **Customer trust** - Some may prefer manual control

## Technical Approach

**To be determined:**
- GitHub App architecture (Probot framework?)
- OAuth flow and token storage
- Webhook handling for app events
- Fallback to manual installation (always available)
- Testing strategy (cannot use act for GitHub Apps)

## Alternative: Keep Manual Installation

**Decision Point:** Is the complexity of a GitHub App worth the UX improvement?

**Pros of Manual:**
- Simpler, no OAuth complexity
- Customer has full control
- Less maintenance burden
- Transparent (customer sees exact workflow)

**Pros of GitHub App:**
- Better UX, one-click setup
- Auto-update workflows
- Competitive parity (other tools do this)

**Recommendation:** Start with manual (RFC-065), build GitHub App later based on customer feedback.

## Next Steps

1. Complete RFC-065 with manual workflow installation
2. Measure setup completion rates and support volume
3. If manual installation is a major friction point, prioritize this RFC
4. Research GitHub App best practices
5. Create detailed implementation plan

## References

- [GitHub Apps Documentation](https://docs.github.com/en/apps)
- [GitHub Contents API](https://docs.github.com/en/rest/repos/contents)
- [Probot Framework](https://probot.github.io/)
