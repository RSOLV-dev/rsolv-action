# RSOLV GitHub Action

Automatically fix issues in your codebase with AI-powered solutions.

## Overview

RSOLV is a GitHub Action that automatically addresses tagged issues in your repository. It uses AI to analyze issues, generate fixes, and create pull requests for your review.

## Security

RSOLV is designed with security as a top priority:

- All code processing happens within your GitHub environment
- Your source code never leaves your repository
- The action runs in an isolated container with minimal permissions

For more information, see our [security architecture documentation](../RSOLV-docs/security/architecture.md).

## Installation

1. Add the RSOLV GitHub Action to your repository
2. Configure your API key as a secret
3. Start tagging issues with "AUTOFIX" to trigger the action

## Usage

### Automated triggering

Tag any issue with "AUTOFIX" to have RSOLV automatically generate a fix.

```yaml
name: RSOLV Automated Fix Generator

on:
  issues:
    types: [labeled]

jobs:
  autofix:
    if: ${{ github.event.label.name == 'AUTOFIX' }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: RSOLV Fix Generator
        uses: rsolv/action@v1
        with:
          api_key: ${{ secrets.RSOLV_API_KEY }}
```

### Manual triggering

You can also manually trigger the action for testing:

1. Go to "Actions" in your repository
2. Select "Manual Trigger for Testing"
3. Input the issue number and repository
4. Click "Run workflow"

## Expert Review

For complex issues, you can request expert review by commenting `/request-expert-review` on the pull request.

## Configuration Options

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `api_key` | Your RSOLV API key | Yes | - |
| `issue_tag` | Tag to identify issues for automation | No | `AUTOFIX` |
| `expert_review_command` | Command to request expert review | No | `/request-expert-review` |

## Support

For questions or issues, please contact support@rsolv.dev or open an issue in this repository.