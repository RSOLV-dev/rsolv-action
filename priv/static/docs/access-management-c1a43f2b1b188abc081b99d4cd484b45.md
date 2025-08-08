# RSOLV Early Access Program - Access Management

This document provides detailed information on managing access to RSOLV during the Early Access Program. As an early access participant, you'll need to understand how to set up and manage access for your team and repositories.

## API Key Management

### Your Primary API Key

Upon acceptance to the Early Access Program, you'll receive a primary API key in your welcome email. This key:

- Is tied to your organization account
- Has full access to RSOLV features
- Should be kept secure and never shared publicly
- Can be used across multiple repositories within your organization

### API Key Security Best Practices

To keep your API key secure:

1. **Store as Secret**: Always store your RSOLV API key as a GitHub Secret
2. **Limit Access**: Restrict access to repository secrets to administrators only
3. **Rotate Regularly**: Generate a new key every 90 days (or if compromised)
4. **Monitor Usage**: Check the RSOLV dashboard for unusual activity
5. **Never Hardcode**: Never include the API key in your workflow files or code

### Additional API Keys

You can generate additional API keys for different teams or projects:

1. Log in to the [RSOLV Dashboard](https://dashboard.rsolv.dev)
2. Go to Settings → API Keys
3. Click "Generate New API Key"
4. Name the key based on its purpose (e.g., "Engineering Team", "Project X")
5. Set appropriate permissions and limitations

## Team Member Access

### Inviting Team Members

To invite team members to your RSOLV Early Access account:

1. Log in to the [RSOLV Dashboard](https://dashboard.rsolv.dev)
2. Navigate to Settings → Team Management
3. Click "Invite Team Member"
4. Enter their email address and select their role
5. Customize access permissions if needed
6. Click "Send Invitation"

### Access Roles

RSOLV offers several access roles for team members:

| Role | Capabilities |
|------|--------------|
| Admin | Full access to all features, settings, and billing |
| Manager | Can manage repositories, view analytics, and configure settings |
| Developer | Can view solutions and PR details, provide feedback |
| Viewer | Read-only access to solutions and analytics |

### Managing Existing Users

To modify access for existing users:

1. Log in to the [RSOLV Dashboard](https://dashboard.rsolv.dev)
2. Navigate to Settings → Team Management
3. Find the user in the list
4. Click the "Edit" button to modify their role or specific permissions
5. Click "Save Changes"

To revoke access:

1. Navigate to Settings → Team Management
2. Find the user in the list
3. Click "Revoke Access"
4. Confirm the action

## Repository Access Management

### Adding Repositories

To add repositories to your RSOLV Early Access account:

1. Log in to the [RSOLV Dashboard](https://dashboard.rsolv.dev)
2. Navigate to Repositories
3. Click "Add Repository"
4. Select from your GitHub organizations/repositories
5. Configure repository-specific settings
6. Click "Add Repository"

### Repository-Specific Settings

For each repository, you can configure:

- **Issue Label**: Customize which label RSOLV should look for (default: "rsolv")
- **PR Handling**: Auto-create, draft-only, or require approval
- **Solution Scope**: Full repository or specific directories
- **Language Models**: Select preferred AI models for this repository
- **PR Reviewers**: Automatically assign specific team members as reviewers

### Repository Access Control

Control which team members can access which repositories:

1. Log in to the [RSOLV Dashboard](https://dashboard.rsolv.dev)
2. Navigate to Repositories
3. Select a repository
4. Click "Manage Access"
5. Add or remove team members and set their repository-specific roles
6. Click "Save Changes"

## GitHub Permissions

### Required GitHub Permissions

RSOLV requires these GitHub permissions to function properly:

- **Read access to code**: To analyze your codebase
- **Read access to issues**: To identify issues tagged for RSOLV
- **Write access to pull requests**: To create PRs with solutions

### GitHub App Installation

If using the GitHub App instead of the Action (beta feature):

1. Visit [github.com/apps/rsolv](https://github.com/apps/rsolv)
2. Click "Install"
3. Select the organization or account
4. Choose "All repositories" or select specific repositories
5. Review and approve the requested permissions

### Restricting Repository Access

To limit which repositories RSOLV can access:

1. Go to your GitHub organization settings
2. Navigate to GitHub Apps → RSOLV
3. Click "Configure"
4. Under "Repository access", select "Only select repositories"
5. Choose the specific repositories
6. Click "Save"

## Usage Limits During Early Access

During the Early Access Program, your account has:

- Up to 100 issue resolutions per month
- Support for repositories up to 500,000 lines of code
- Up to 15 team members
- Up to 10 repositories

To request increased limits, email early-access@rsolv.dev.

## Audit Logging

All access events are logged for security and transparency:

1. Log in to the [RSOLV Dashboard](https://dashboard.rsolv.dev)
2. Navigate to Settings → Audit Logs
3. View a complete history of:
   - API key generation and usage
   - User login activity
   - Permission changes
   - Repository additions and removals
   - PR creation and interaction

## Enterprise SSO Integration (Beta)

For organizations requiring SSO integration:

1. Contact your Early Access representative
2. Provide details of your SSO provider (Okta, Azure AD, etc.)
3. We'll provide custom setup instructions for your environment

## Compliance and Data Handling

RSOLV's access management adheres to:

- SOC 2 Type II compliance
- GDPR data protection requirements
- GitHub's security best practices

Your code never leaves your GitHub Actions environment unless explicitly configured for expert review.

## Troubleshooting Access Issues

If you encounter access problems:

1. Verify API key is correctly set as a GitHub Secret
2. Check repository permissions in GitHub
3. Ensure the team member has the appropriate role
4. Verify workflow file is correctly configured
5. Check GitHub Action logs for specific errors

For persistent issues, contact support@rsolv.dev.

---

For additional help with access management, contact your Early Access representative or email early-access@rsolv.dev.