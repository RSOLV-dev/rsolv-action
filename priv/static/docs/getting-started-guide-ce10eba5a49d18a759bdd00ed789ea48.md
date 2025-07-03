# RSOLV Getting Started Guide

Welcome to RSOLV, the AI-powered GitHub Action that automatically resolves issues in your repository backlog. This guide will help you quickly set up RSOLV and start reclaiming your engineering team's valuable time.

## Quick Setup (15 Minutes)

RSOLV is designed to integrate seamlessly with your GitHub workflow with minimal setup time and zero disruption to your existing processes.

### Prerequisites
- GitHub repository with an issue backlog
- Admin access to the repository
- GitHub Actions enabled

### Installation Steps

1. **Add the GitHub Action**

   Create a new file at `.github/workflows/rsolv.yml` with the following content:

   ```yaml
   name: RSOLV Backlog Automation
   on:
     schedule:
       - cron: '0 0 * * *'  # Run daily at midnight
     workflow_dispatch:     # Allow manual triggers
     
   jobs:
     autofix:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v3
           with:
             fetch-depth: 0
         
         - name: Run RSOLV
           uses: rsolv/autofix-action@v1
           with:
             api-key: ${{ secrets.RSOLV_API_KEY }}
             issue-label: "rsolv"  # Customize this label if needed
   ```

2. **Set Up Your API Key**

   - Go to your repository → Settings → Secrets and variables → Actions
   - Add a new repository secret named `RSOLV_API_KEY` with the value from your welcome email

3. **Tag Issues for Resolution**

   Add the `rsolv` label (or your custom label) to issues you want RSOLV to address.

4. **Trigger Your First Run**

   - Go to your repository → Actions tab
   - Select "RSOLV Backlog Automation" workflow
   - Click "Run workflow"
   - Wait for the action to complete (typically 2-5 minutes)

## What to Expect

### Week 1: Initial Results
- First automated fixes start appearing as pull requests
- Each PR includes detailed explanations and tests
- Human-friendly explanations of all code changes

### Month 1: Measurable Impact
- Noticeable reduction in routine issue backlog
- Engineering time saved on straightforward fixes
- Clearly tracked metrics in your RSOLV dashboard

### Month 3: Significant ROI
- 65%+ backlog reduction for applicable issues
- 30-50% reduction in PR cycle time for routine fixes
- Measurable reclaiming of engineering resources (23-42%)

## Best Issue Types for RSOLV

RSOLV excels at handling these types of issues:

| Issue Type | Examples | Success Rate |
|------------|----------|--------------|
| **Bug Fixes** | Null pointer errors, type mismatches, off-by-one errors | 75-85% |
| **Performance Optimizations** | Query efficiency, rendering performance, memory leaks | 65-80% |
| **Dependency Updates** | Library version bumps with breaking changes reconciliation | 90-95% |
| **Code Quality Improvements** | Refactoring, DRY principle application, pattern consistency | 70-85% |
| **Documentation Updates** | Adding JSDoc, improving README, API documentation | 85-95% |

## Key Differentiators from Dependabot

Unlike Dependabot which only handles dependency updates, RSOLV offers:

1. **Comprehensive Issue Coverage**
   - Resolves bugs, performance issues, and code quality fixes
   - Handles any issue type with clear description, not just dependencies

2. **Intelligent Code Understanding**
   - Understands your codebase patterns and conventions
   - Reconciles breaking changes intelligently
   - Adapts solutions to match your specific coding style

3. **Complete Pull Requests**
   - Includes tests, documentation, and detailed explanations
   - Addresses complex, multi-file changes when needed
   - Handles edge cases beyond simple version bumps

## Enterprise-Ready Integration

RSOLV is designed to meet enterprise requirements:

### Security & Compliance
- SOC2 compliant with comprehensive audit logging
- Configurable approval workflows for all code changes
- Transparent AI decision explanations
- Enterprise SSO integration

### Integration Flexibility
- Works alongside existing CI/CD pipelines and tools
- Opt-in/opt-out controls for specific repositories or issue types
- Progressive complexity model - start simple, add features as needed
- Clear dashboards showing activity and impact metrics

## Advanced Configuration

For more control over how RSOLV works, create a `.rsolv.yml` file in your repository root:

```yaml
# RSOLV Configuration
version: 1

# Issue label that triggers RSOLV
label: "auto-fix"  # Default: "rsolv"

# Branch prefix for created PRs
branch_prefix: "autofix/"  # Default: "rsolv/"

# Additional files to ignore
ignore_patterns:
  - "*.test.js"
  - "docs/*"

# Reviewer assignment
assign_reviewers: true  # Default: false

# Solution quality level
quality: "thorough"  # Options: "draft", "standard", "thorough"

# PR review requirements
review_required: true  # Default: true
```

## Measuring Your ROI

RSOLV provides clear metrics to measure your return on investment:

### Dashboard Metrics
- Issues resolved automatically
- Engineering hours saved
- Backlog reduction percentage
- Average resolution time
- Success rate by issue type

### Calculating Time Savings
1. Average time to manually fix similar issues × Number of resolved issues
2. Apply your engineering hourly cost to calculate dollar savings
3. Compare to RSOLV subscription cost for ROI percentage

Most teams see positive ROI within 3-6 months, with many achieving breakeven in as little as 1-2 months.

## Support and Resources

If you need assistance or have questions:

- **Email Support**: support@rsolv.dev
- **Documentation**: [docs.rsolv.dev](https://docs.rsolv.dev)
- **Office Hours**: Tuesday & Thursday, 10am-12pm PT
- **Discord Community**: [Join our Discord](https://discord.gg/rsolv)

## Next Steps

1. **Complete Setup**: Follow the quick setup steps above
2. **Tag Initial Issues**: Start with 5-10 well-defined issues
3. **Review First PRs**: Provide feedback on your first automated fixes
4. **Schedule Onboarding Call**: Use the link in your welcome email
5. **Explore Advanced Features**: Check out our [Configuration Guide](https://docs.rsolv.dev/configuration)

Thank you for joining RSOLV's Early Access Program! We're excited to help you reclaim engineering time and address your backlog more efficiently.