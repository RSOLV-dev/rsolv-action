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

## Expert Review & Feedback Loop

For complex issues, you can request expert review by commenting `/request-expert-review` on the pull request.

### Feedback System

RSOLV incorporates a sophisticated feedback loop system that:

1. Captures feedback from expert reviews, PR comments, and edits
2. Analyzes sentiment and extracts useful patterns
3. Enhances future AI prompts based on historical feedback
4. Continuously improves solution quality over time

```mermaid
flowchart LR
    A[Expert Review] --> B[Feedback Event]
    B --> C[Feedback Store]
    C --> D[Prompt Enhancer]
    D --> E[AI Solution Generator]
```

## Configuration Options

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `api_key` | Your RSOLV API key | Yes | - |
| `issue_tag` | Tag to identify issues for automation | No | `AUTOFIX` |
| `expert_review_command` | Command to request expert review | No | `/request-expert-review` |

## Support

For questions or issues, please contact support@rsolv.dev or open an issue in this repository.

## Continuous Integration

This project is configured with automated CI pipelines through both GitHub Actions and SourceHut:

- **GitHub Actions**: Primary CI system for push/PR validation and releases
- **SourceHut**: Secondary CI system that offers lightweight, text-focused builds

### CI Status
[![Build Status (GitHub)](https://github.com/arboreal-studios/RSOLV-action/actions/workflows/ci.yml/badge.svg)](https://github.com/arboreal-studios/RSOLV-action/actions)
[![builds.sr.ht status](https://builds.sr.ht/~arubis/rsolv-action.svg)](https://builds.sr.ht/~arubis/rsolv-action?)

## License

Proprietary. Copyright (c) 2024-2025 Arboreal Studios, Inc. All rights reserved.

See [LICENSE.md](LICENSE.md) for details.