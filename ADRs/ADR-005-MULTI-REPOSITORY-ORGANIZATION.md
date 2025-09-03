# ADR-005: Multi-Repository Organization

**Status**: Implemented  
**Date**: 2025-05-20  
**Authors**: Infrastructure Team  

## Context

RSOLV started as a monolithic repository containing all components. As the platform grew, we faced several organizational challenges:

- **Deployment Coupling**: Changes to documentation triggered unnecessary deployments
- **Development Friction**: Different teams stepping on each other's work
- **Release Coordination**: Business docs updates delayed technical releases  
- **Permission Management**: Difficulty controlling access to sensitive components
- **CI/CD Complexity**: Single pipeline handling disparate technologies
- **Dependency Conflicts**: Node.js, Elixir, and documentation tools in same repo

The decision was whether to maintain a monorepo for simplicity or split into focused repositories for better separation of concerns.

## Decision

We implemented a **multi-repository architecture** with 5 independent repositories organized by function and technology:

### Repository Structure

```
rsolv/ (main coordination repository)
├── RSOLV-action/ (independent git repository)
├── RSOLV-api/ (independent git repository) 
├── RSOLV-docs/ (independent git repository)
├── rsolv-landing/ (independent git repository)
└── biz-plan/ (directory in main repository)
```

### Repository Responsibilities

1. **Main Repository (`rsolv`)**
   - **Purpose**: Project coordination and business planning
   - **Technology**: Markdown documentation
   - **Contains**: High-level project files, RFCs, ADRs, business documents
   - **Deployment**: None (documentation only)

2. **RSOLV-action**
   - **Purpose**: GitHub Action implementation  
   - **Technology**: TypeScript with Bun runtime
   - **Contains**: Core functionality, AI integration, issue analysis
   - **Deployment**: GitHub Container Registry → Docker Hub

3. **RSOLV-api**
   - **Purpose**: API service for credential vending and webhooks
   - **Technology**: Elixir/Phoenix
   - **Contains**: Credential management, webhook handling, billing logic
   - **Deployment**: Kubernetes on DigitalOcean

4. **rsolv-landing**
   - **Purpose**: Customer-facing website and early access portal
   - **Technology**: Elixir/Phoenix web application
   - **Contains**: Landing page, signup flow, analytics
   - **Deployment**: Kubernetes with TLS

5. **RSOLV-docs**
   - **Purpose**: Comprehensive documentation
   - **Technology**: Markdown with documentation tooling
   - **Contains**: Technical guides, architecture docs, user guides
   - **Deployment**: Synced to landing page static docs

### Git Configuration

**Nested Repository Setup**:
- Each nested directory is a complete git repository
- Main repository `.gitignore` excludes nested repo directories
- Independent commit histories and branching strategies
- Separate CI/CD pipelines for each repository

**Repository URLs**:
- Main: `https://github.com/RSOLV-dev/RSOLV-base`
- Action: `https://github.com/RSOLV-dev/rsolv-action`
- API: `https://github.com/RSOLV-dev/rsolv-api`
- Landing: `https://github.com/RSOLV-dev/rsolv-landing`
- Docs: `https://github.com/RSOLV-dev/rsolv-docs`

## Consequences

### Positive

- **Independent Deployment**: Each component deploys separately
- **Team Autonomy**: Frontend, backend, and docs teams work independently
- **Technology Freedom**: Each repo uses optimal technology stack
- **Access Control**: Granular permissions per repository
- **CI/CD Simplicity**: Focused pipelines per technology
- **Release Independence**: Documentation updates don't block feature releases

### Trade-offs

- **Coordination Overhead**: Cross-repo changes require coordination
- **Dependency Management**: Manual coordination of API contracts
- **Development Setup**: Developers need multiple repo checkouts
- **Integration Testing**: More complex to test across repositories
- **Documentation Drift**: Docs can get out of sync with implementation

### Business Impact

- **Development Velocity**: Teams can move faster independently
- **Risk Reduction**: Issues in one component don't affect others
- **Hiring Flexibility**: Can hire specialists for specific technologies
- **Open Source Strategy**: Can selectively open-source components
- **Partnership Opportunities**: Easier to share specific components

## Implementation Evidence

**Repository Structure**: Verified independent git repositories

**Deployment Independence**:
- ✅ RSOLV-action: Published to GitHub Container Registry
- ✅ RSOLV-api: Deployed to Kubernetes (api.rsolv.dev)
- ✅ rsolv-landing: Deployed to Kubernetes (rsolv.dev)
- ✅ RSOLV-docs: Documentation tooling operational

**Development Workflow**:
- Independent branching strategies per repository
- Separate CI/CD pipelines configured
- Cross-repo dependency management via APIs

**Access Control**:
- Repository-specific permission management
- Secret management scoped to repositories
- Independent security scanning per repo

## Related Decisions

- **ADR-001**: Credential Vending (API-Action communication contract)
- **ADR-002**: Webhook Infrastructure (API-specific deployment)

## Development Workflow

### Making Changes

```bash
# For RSOLV-action changes
cd RSOLV-action
git commit -m "Add new feature"
git push origin main

# For RSOLV-api changes  
cd RSOLV-api
git commit -m "Update API endpoint"
git push origin main

# Main repo for coordination
git commit -m "Update project documentation"
git push origin main
```

### Cross-Repository Dependencies

1. **API Contracts**: Documented interfaces between Action and API
2. **Version Coordination**: Semantic versioning for breaking changes
3. **Integration Testing**: Automated tests across repository boundaries
4. **Documentation Sync**: Automated sync from RSOLV-docs to landing page

## Future Considerations

1. **Monorepo Tools**: Consider tools like Nx if coordination becomes complex
2. **Shared Libraries**: Extract common code to shared packages
3. **API Versioning**: Formal API versioning strategy for breaking changes
4. **Documentation Automation**: Automated doc generation from code

## Migration History

- **Before**: Single monolithic repository with all components
- **Migration**: Extracted each component to independent repository
- **Result**: 5 focused repositories with clear boundaries
- **Verification**: Independent deployments operational

## References

- Repository Structure: `CLAUDE.md` (Repository Structure section)
- Git Configuration: `.gitignore` and individual repository settings
- Deployment Guides: Each repository contains deployment documentation