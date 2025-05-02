# RSOLV GitHub Action

Automate fixing issues in your repository using AI.

## Overview

RSOLV is a GitHub Action that helps software development teams address their maintenance backlog by automatically fixing issues. The action connects to your issue tracker, identifies items tagged for automation, uses AI to analyze and fix issues, and creates clean pull requests for human review.

## Features

- 🔍 Automatically detects issues tagged for automation
- 🤖 Uses AI to analyze issues and generate solutions
- 🛡️ Runs in a secure, containerized environment
- 🔀 Creates pull requests with detailed descriptions
- 🔗 Supports external issue trackers (Jira, Linear)
- 🔐 Secure by design - no source code leaves your repository

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
        uses: rsolv-dev/action@v1
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

## Environment Variables

The following environment variables can be used to configure the action:

- `RSOLV_API_KEY`: Your RSOLV API key (required)
- `RSOLV_CONFIG_PATH`: Path to the configuration file (default: `.github/rsolv.yml`)
- `RSOLV_ISSUE_LABEL`: Label to identify issues for automation (default: `rsolv:automate`)
- `RSOLV_ENVIRONMENT_VARIABLES`: JSON string of environment variables to pass to the container

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
```

## License

MIT License

## Support

For support, email support@rsolv.dev or open an issue on GitHub.