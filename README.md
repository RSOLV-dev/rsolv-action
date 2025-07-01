# RSOLV GitHub Action

Automate fixing issues in your repository using AI.

## Overview

RSOLV is a GitHub Action that helps software development teams address their maintenance backlog by automatically fixing issues. The action connects to your issue tracker, identifies items tagged for automation, uses AI to analyze and fix issues, and creates clean pull requests for human review.

## Features

- 🔍 **Proactive Scanning**: Scan repositories for vulnerabilities before they're reported
- 🤖 Uses AI to analyze issues and generate solutions
- 🛡️ Runs in a secure, containerized environment
- 🔀 Creates pull requests with detailed descriptions
- 🔗 Supports external issue trackers (Jira, Linear, GitLab coming soon)
- 🔐 Secure by design - no source code leaves your repository
- 🔑 Single API key - no AI provider accounts needed
- 🎯 **Find & Fix**: Complete workflow from vulnerability detection to remediation

## Security Features

RSOLV provides comprehensive security analysis and remediation:

- **448+ Security Patterns**: Enterprise-grade vulnerability detection across 8 languages
- **Dynamic Pattern Updates**: Patterns served via API for real-time security updates
- **OWASP Top 10 Coverage**: Complete coverage of the most critical web application security risks
- **Framework-Specific Patterns**: Specialized detection for Rails, Django, Phoenix, React, Express, and more
- **Real-Time Detection**: Analyzes code changes for security vulnerabilities during issue processing
- **Compliance Documentation**: Generates SOC2, PCI-DSS, ISO27001, GDPR, and HIPAA compliance evidence
- **Educational Explanations**: Every fix includes tiered explanations to help teams learn and prevent future issues

### Supported Security Patterns

- **Injection**: SQL, NoSQL, Command, LDAP, Template, and XPath injection detection
- **XSS**: React dangerouslySetInnerHTML, innerHTML, document.write patterns
- **Authentication**: JWT vulnerabilities, weak sessions, missing auth checks
- **Access Control**: Missing authorization, CSRF, unvalidated redirects
- **Cryptographic Failures**: Weak encryption, hardcoded secrets, insecure storage
- **Misconfiguration**: CORS, security headers, debug mode exposure
- **Vulnerable Components**: Outdated dependencies, dangerous functions
- **SSRF**: Server-side request forgery with DNS rebinding protection
- **And more**: Path traversal, prototype pollution, XXE, and deserialization

## Installation

Add the following to your workflow file:

```yaml
name: RSOLV Automation

on:
  issues:
    types: [opened, labeled, edited]
  schedule:
    - cron: '0 */6 * * *'  # Run every 6 hours

jobs:
  automate:
    runs-on: ubuntu-latest
    steps:
      - name: Run RSOLV
        uses: RSOLV-dev/rsolv-action@v2
        with:
          api_key: ${{ secrets.RSOLV_API_KEY }}
          issue_label: 'rsolv:automate'  # Optional: custom label
```

## Configuration

RSOLV can be configured using a `.github/rsolv.yml` file in your repository:

```yaml
# AI Provider configuration
aiProvider:
  provider: anthropic  # anthropic, openai, mistral, or ollama
  model: claude-3-sonnet-20240229
  useVendedCredentials: true  # Use RSOLV's credential vending service
  temperature: 0.2
  maxTokens: 4000

# Container configuration
containerConfig:
  enabled: true
  image: rsolv/code-analysis:latest
  memoryLimit: 2g
  cpuLimit: 1
  timeout: 300
  securityProfile: default

# Security settings
securitySettings:
  disableNetworkAccess: true
  scanDependencies: true
  preventSecretLeakage: true
  maxFileSize: 1048576  # 1 MB
  timeoutSeconds: 300
  requireCodeReview: true
```

## Proactive Security Scanning

RSOLV can proactively scan your repository for vulnerabilities and create issues for discovered problems:

```yaml
name: Weekly Security Scan
on:
  schedule:
    - cron: '0 0 * * 1'  # Weekly on Mondays

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: RSOLV-dev/rsolv-action@main
        with:
          api_key: ${{ secrets.RSOLV_API_KEY }}
          scan_mode: scan  # Enable proactive scanning
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

This will:
1. Scan your entire repository for security vulnerabilities
2. Group similar vulnerabilities together
3. Create GitHub issues with detailed descriptions
4. Apply the `rsolv:automate` label for processing

See [docs/SCAN-MODE.md](docs/SCAN-MODE.md) for complete documentation.

## Enhanced Context and Performance Optimizations

RSOLV includes several features for optimizing performance and token usage:

### Single-Pass Processing (Default)

RSOLV now uses single-pass processing by default, combining context gathering and solution generation:

```yaml
# Single-pass is enabled by default - no configuration needed
# To enable enhanced context (two-pass) mode:
- uses: RSOLV-dev/rsolv-action@v1
  with:
    enable_enhanced_context: 'true'
```

### Features

- **Single-Pass Processing**: Reduces token usage by ~50% and processing time by 40-60%
- **Credential Singleton**: Prevents multiple API authentications, improving reliability
- **AI Conversation Logging**: Debug AI interactions for troubleshooting (development only)
- **Enhanced Pattern Support**: Supports latest API patterns with regex field handling

### Advanced Configuration

For scenarios requiring deeper analysis, you can enable enhanced context:

```yaml
# Enable enhanced context for complex issues
- uses: RSOLV-dev/rsolv-action@v1
  with:
    api_key: ${{ secrets.RSOLV_API_KEY }}
    enable_enhanced_context: 'true'  # Opt-in for deeper analysis
  env:
    RSOLV_CONTEXT_DEPTH: 'deep'  # shallow, medium, deep, or ultra
```

### Debugging AI Conversations (Development Only)

For debugging AI interactions during development:

```yaml
# Enable conversation logging
env:
  AI_CONVERSATION_LOG_LEVEL: 'full'  # or 'summary' or 'none'
  AI_CONVERSATION_LOG_DIR: '/tmp/ai-conversation-logs'

# Upload logs as artifacts
- name: Upload AI Conversation Logs
  uses: actions/upload-artifact@v4
  if: always()
  with:
    name: ai-conversation-logs
    path: /tmp/ai-conversation-logs/
```

**Note**: This feature is for development only and should be removed before production use.

### Configuration

```yaml
# Advanced configuration
env:
  RSOLV_CLAUDE_CODE_CONFIG: |
    {
      "enableDeepContext": true,
      "enableUltraThink": true,
      "contextDepth": "ultra",
      "contextGatheringTimeout": 300000,
      "analyzeArchitecture": true,
      "analyzeTestPatterns": true,
      "analyzeStyleGuide": true,
      "contextOptions": {
        "includeDirs": ["src", "lib", "tests"],
        "excludeDirs": ["node_modules", "dist"]
      }
    }
```

For more details, see:
- [Enhanced Context Guide](docs/ENHANCED-CONTEXT-GUIDE.md)
- [Prompts Architecture](docs/PROMPTS-ARCHITECTURE.md)

## Credential Vending Service

RSOLV simplifies AI integration by providing a credential vending service:

- **Single API Key**: Just one RSOLV API key - we manage all AI provider relationships
- **Temporary Credentials**: Secure, time-limited AI provider credentials
- **Direct API Access**: GitHub Action makes direct API calls for optimal performance
- **Usage Tracking**: Automatically tracks AI usage for billing

How it works:
1. GitHub Action exchanges RSOLV API key for temporary AI provider credentials
2. Temporary credentials are used to make direct API calls
3. Credentials automatically expire after 1 hour
4. All usage is tracked and billed to your RSOLV account

To use:
```yaml
aiProvider:
  useVendedCredentials: true  # Enable credential vending
```

## Environment Variables

The following environment variables can be used to configure the action:

- `RSOLV_API_KEY`: Your RSOLV API key (required)
- `RSOLV_API_URL`: API endpoint (default: `https://api.rsolv.dev`)
- `RSOLV_CONFIG_PATH`: Path to the configuration file (default: `.github/rsolv.yml`)
- `RSOLV_ISSUE_LABEL`: Label to identify issues for automation (default: `rsolv:automate`)
- `RSOLV_ENVIRONMENT_VARIABLES`: JSON string of environment variables to pass to the container

## External Issue Trackers

RSOLV supports multiple issue tracking platforms beyond GitHub Issues:

### Jira Integration

```bash
# Set Jira credentials
export JIRA_HOST="your-domain.atlassian.net"
export JIRA_EMAIL="your-email@example.com"
export JIRA_API_TOKEN="your-jira-api-token"

# Optional: Custom labels (defaults shown)
export JIRA_AUTOFIX_LABEL="autofix"
export JIRA_RSOLV_LABEL="rsolv"
```

See [Jira Integration Guide](docs/jira-integration.md) for detailed setup.

### Linear Integration

```bash
# Set Linear API key
export LINEAR_API_KEY="lin_api_YOUR_KEY_HERE"

# Optional: Team ID and custom labels
export LINEAR_TEAM_ID="your-team-id"
export LINEAR_AUTOFIX_LABEL="autofix"
export LINEAR_RSOLV_LABEL="rsolv"
```

See [Linear Integration Guide](docs/linear-integration.md) for detailed setup.

### GitLab Integration (Coming Soon)

GitLab issue tracking integration is under development.

## Troubleshooting

### Common Issues

#### File paths in GitHub Issues

When creating issues that reference file paths, always use **relative paths** instead of absolute paths:

- ✅ **Correct**: `app/data/allocations-dao.js`
- ❌ **Wrong**: `/app/data/allocations-dao.js`

**Why?** GitHub Actions runs in a containerized environment where the repository is mounted at `/github/workspace`. Absolute paths will cause RSOLV to look in the wrong location and either fail to find files or create new files in unexpected places.

**Example Issue Body**:
```markdown
There is a NoSQL injection vulnerability in app/data/allocations-dao.js at line 78.
The code uses string interpolation in a MongoDB $where clause.
```

#### Pull Request Creation Failures

If RSOLV fails to create a pull request:
1. Check that the workflow has `contents: write` and `pull-requests: write` permissions
2. Verify the GITHUB_TOKEN is properly configured
3. Check action logs for specific error messages

#### Timeout Issues

For complex vulnerabilities, RSOLV may take longer than expected:
- Default timeout is 60 minutes
- Can be adjusted in your workflow configuration
- Consider processing one issue at a time for complex fixes

## Development

### Prerequisites

- [Bun](https://bun.sh/) (latest version)
- Docker (for container testing)

### Setup

```bash
# Clone the repository
git clone https://github.com/rsolv-dev/action.git
cd action

# Install dependencies
bun install

# Run tests
bun test

# Type check
bun run typecheck

# Lint
bun run lint
```

### Testing

```bash
# Run tests
bun test

# Run tests in watch mode
bun test --watch

# Run tests in isolation (recommended for CI/CD)
# This avoids mock pollution issues between test files
bun run test:isolated
```

**Note**: Due to Bun's test framework limitations, some tests may fail when run together but pass individually. Use `test:isolated` for accurate results.

## License

MIT License

## Support

For support, email support@rsolv.dev or open an issue on GitHub.# Trigger Docker rebuild with credential manager fix
