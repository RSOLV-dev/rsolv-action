# RSOLV Advanced Configuration Guide

This guide provides detailed information on advanced configuration options for RSOLV. While the default configuration works well for most repositories, these advanced settings allow you to customize RSOLV's behavior to better suit your specific needs and workflows.

## Configuration File

For advanced configuration, you can create a `.rsolv/config.json` file in the root of your repository:

```json
{
  "version": "1.0",
  "issue": {
    "label": "rsolv",
    "maxPerRun": 5,
    "priority": {
      "enabled": true,
      "labels": {
        "high": ["priority-high", "p1"],
        "medium": ["priority-medium", "p2"],
        "low": ["priority-low", "p3"]
      }
    },
    "exclude": {
      "labels": ["wontfix", "question"]
    }
  },
  "solution": {
    "quality": "standard",
    "models": {
      "default": "claude",
      "fallback": "ollama"
    },
    "contextSize": "auto"
  },
  "pullRequest": {
    "draft": true,
    "reviewRequired": true,
    "assignees": ["@team/engineering"],
    "branchPrefix": "rsolv/",
    "template": ".github/PULL_REQUEST_TEMPLATE.md"
  },
  "security": {
    "scanningLimits": {
      "maxFiles": 5000,
      "maxFileSize": 1048576,
      "excludePaths": ["node_modules/**", "vendor/**", "**/generated/**"]
    },
    "sensitivity": {
      "excludePatterns": [
        "(?i)api[-_]?key",
        "(?i)secret",
        "(?i)password",
        "(?i)credential"
      ]
    }
  },
  "telemetry": {
    "enabled": true,
    "detailed": false
  },
  "expertReview": {
    "enabled": false,
    "email": "experts@example.com",
    "maxRequestsPerDay": 3
  },
  "prompts": {
    "enhance": {
      "styleGuide": "Follow our coding style with 2-space indentation, explicit return types, and avoid abbreviations.",
      "architecture": "Our application follows a clean architecture pattern with controllers, services, and repositories."
    }
  }
}
```

## Issue Configuration

### Priority Management

RSOLV can prioritize issues based on labels:

```json
"priority": {
  "enabled": true,
  "labels": {
    "high": ["priority-high", "p1", "urgent"],
    "medium": ["priority-medium", "p2", "normal"],
    "low": ["priority-low", "p3", "minor"]
  }
}
```

RSOLV will process high-priority issues first, then medium, then low.

### Issue Exclusion

Exclude specific issues from processing:

```json
"exclude": {
  "labels": ["wontfix", "question", "discussion"],
  "titlePatterns": ["\\[WIP\\].*"],
  "authors": ["dependabot"]
}
```

### Issue Selection Criteria

Customize how RSOLV selects which issues to process:

```json
"selection": {
  "strategy": "oldest_first", // Options: "oldest_first", "newest_first", "priority_based"
  "minimumComments": 0,
  "maximumAge": "90d", // Issues older than this won't be processed
  "requiresAssignee": false
}
```

## Solution Generation

### Quality Levels

RSOLV offers three quality levels for solution generation:

1. **draft** - Faster but less refined solutions suitable for internal PRs
2. **standard** - Balanced quality and speed (default)
3. **thorough** - Highest quality solutions with extensive testing and documentation

```json
"quality": "thorough" // Options: "draft", "standard", "thorough"
```

### AI Model Selection

```json
"models": {
  "default": "claude", // Primary model
  "fallback": "ollama", // Used if primary model fails
  "customEndpoint": "http://internal-ai-service:8080/generate" // Optional
}
```

When using a custom endpoint, RSOLV will format requests according to standards for that model family.

### Context Configuration

Control how much context RSOLV gathers from your codebase:

```json
"context": {
  "size": "auto", // Options: "minimal", "standard", "extensive", "auto"
  "maxTokens": 100000,
  "referencedFilesWeight": 3, // Higher values prioritize files referenced in the issue
  "relativeDirWeight": 2, // Higher values prioritize files in the same directory
  "includePatterns": ["**/*.js", "**/*.ts"],
  "excludePatterns": ["**/*.test.js", "**/*.spec.ts"]
}
```

## Pull Request Configuration

### PR Creation Options

```json
"pullRequest": {
  "draft": true, // Create as draft PR
  "reviewRequired": true, // Require review before merge
  "autoMerge": false, // Auto-merge when CI passes and required reviews received
  "assignees": ["@username", "@team/engineering"], // Auto-assign
  "labels": ["ai-generated", "needs-review"],
  "branchPrefix": "rsolv/",
  "deleteBranchOnMerge": true,
  "template": ".github/PULL_REQUEST_TEMPLATE.md" // Custom PR template
}
```

### PR Description Customization

Customize the PR description template:

```json
"description": {
  "template": "## Solution\n{{solution_summary}}\n\n## Changes\n{{file_changes}}\n\n## Testing\n{{testing_notes}}",
  "includeIssueBody": true,
  "includeTestInstructions": true
}
```

## Security Settings

### Repository Scanning Limitations

Control what parts of your repository RSOLV can access:

```json
"scanningLimits": {
  "maxFiles": 5000, // Maximum number of files to scan
  "maxFileSize": 1048576, // Maximum file size in bytes (1MB)
  "maxRepositorySize": 1073741824, // Maximum repository size in bytes (1GB)
  "excludePaths": [
    "node_modules/**", 
    "vendor/**", 
    "dist/**", 
    "build/**",
    "**/generated/**"
  ],
  "includePaths": ["src/**", "lib/**"] // If specified, only these paths will be scanned
}
```

### Sensitive Information Protection

Control how RSOLV handles potentially sensitive content:

```json
"sensitivity": {
  "excludePatterns": [
    "(?i)api[-_]?key",
    "(?i)secret",
    "(?i)password",
    "(?i)credential",
    "(?i)token"
  ],
  "excludeFiles": [
    ".env*",
    "**/*.key",
    "**/credentials.*"
  ],
  "redactionToken": "[REDACTED]"
}
```

### Data Processing Limitations

```json
"dataProcessing": {
  "codeStaysLocal": true, // RSOLV will only process code within GitHub Actions
  "anonymizeIssues": false, // Strip identifying information from issues 
  "allowExternalApis": false // Allow RSOLV to call external APIs for research
}
```

## Custom Prompts

### Solution Generation Guidance

Provide additional context to guide RSOLV's solution generation:

```json
"prompts": {
  "enhance": {
    "styleGuide": "Our codebase follows Google's style guide with these exceptions: we use 2-space indentation and explicit return types.",
    "architecture": "Our application uses a service-oriented architecture where each feature has its own directory containing models, controllers, and services.",
    "testingStrategy": "We practice TDD with Jest. Every component should have a corresponding test file."
  }
}
```

### Domain-Specific Knowledge

Provide domain knowledge to improve RSOLV's understanding:

```json
"domainKnowledge": {
  "terminology": {
    "STH": "Subscription Transaction History",
    "RTM": "Real-Time Monitoring",
    "PCM": "Pricing Calculation Module"
  },
  "conceptualLinks": [
    "Customer and Account have a one-to-many relationship",
    "All financial transactions must be validated by the Security module",
    "Notifications are handled by the Event Bus system"
  ]
}
```

## Expert Review System

Configure RSOLV's expert review feature:

```json
"expertReview": {
  "enabled": true,
  "email": "dev-team@example.com",
  "threshold": {
    "complexity": "high",
    "uncertainty": 0.7
  },
  "provideFeedback": true,
  "maxRequestsPerDay": 5
}
```

## Environment Variables

In addition to the configuration file, you can use environment variables for sensitive settings or to override configuration:

| Environment Variable | Description | Default |
|----------------------|-------------|---------|
| `RSOLV_API_KEY` | API key for RSOLV services | Required |
| `RSOLV_ISSUE_LABEL` | Override issue label | From config |
| `RSOLV_MAX_ISSUES` | Override max issues per run | From config |
| `RSOLV_SOLUTION_QUALITY` | Override solution quality | From config |
| `RSOLV_MODEL` | Override AI model | From config |
| `RSOLV_EXPERT_EMAIL` | Override expert review email | From config |
| `RSOLV_GITHUB_TOKEN` | Custom GitHub token | `secrets.GITHUB_TOKEN` |
| `RSOLV_LOG_LEVEL` | Set logging level | `info` |

## Workflow Examples

### Scheduled Low-Priority Issue Resolution

```yaml
name: RSOLV Weekend Cleanup
on:
  schedule:
    - cron: '0 0 * * 6'  # Run at midnight on Saturdays
jobs:
  autofix-low-priority:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run RSOLV
        uses: rsolv/autofix-action@v1
        with:
          api-key: ${{ secrets.RSOLV_API_KEY }}
          config-override: '{"issue":{"priority":{"enabled":true,"labels":{"low":["low-priority","p3","nice-to-have"]}}},"solution":{"quality":"draft"},"pullRequest":{"draft":true}}'
```

### Sensitive Repository Configuration

For repositories with sensitive data:

```yaml
name: RSOLV Secure Mode
on:
  workflow_dispatch:
jobs:
  autofix-secure:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run RSOLV
        uses: rsolv/autofix-action@v1
        with:
          api-key: ${{ secrets.RSOLV_API_KEY }}
          config-override: '{"security":{"scanningLimits":{"maxFiles":1000,"excludePaths":["**/credentials/**","**/secrets/**","**/personal-data/**"]},"sensitivity":{"excludePatterns":["(?i)key","(?i)secret","(?i)pass","(?i)credential","(?i)token","(?i)auth","(?i)ssn","(?i)personal"]}},"dataProcessing":{"codeStaysLocal":true,"anonymizeIssues":true,"allowExternalApis":false}}'
```

## Language-Specific Configurations

### JavaScript/TypeScript

```json
"prompts": {
  "enhance": {
    "styleGuide": "We follow the Airbnb JavaScript Style Guide with TypeScript extensions.",
    "architecture": "We use React with a Redux state management pattern.",
    "packageManager": "yarn",
    "testFramework": "jest"
  }
}
```

### Python

```json
"prompts": {
  "enhance": {
    "styleGuide": "We follow PEP 8 with a 100-character line limit.",
    "architecture": "We use a Flask-based microservices architecture.",
    "dependencyManagement": "We use poetry for dependency management.",
    "testFramework": "pytest"
  }
}
```

### Java

```json
"prompts": {
  "enhance": {
    "styleGuide": "We follow Google Java Style Guide.",
    "architecture": "We use Spring Boot with a hexagonal architecture pattern.",
    "buildTool": "maven",
    "testFramework": "junit5"
  }
}
```

## FAQ

### Can I use different AI models for different types of issues?

Yes, you can set up multiple workflow files with different configurations:

```yaml
# .github/workflows/rsolv-docs.yml
name: RSOLV Documentation Tasks
on:
  workflow_dispatch:
    inputs:
      issue_number:
        description: 'Issue number to process'
        required: true
jobs:
  autofix-docs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run RSOLV
        uses: rsolv/autofix-action@v1
        with:
          api-key: ${{ secrets.RSOLV_API_KEY }}
          issue-number: ${{ github.event.inputs.issue_number }}
          config-override: '{"issue":{"labels":["documentation"]},"solution":{"models":{"default":"claude"}}}'
```

### How can I limit RSOLV to certain file types?

Use the scanning limits configuration:

```json
"scanningLimits": {
  "includePaths": ["src/**/*.js", "src/**/*.ts", "src/**/*.tsx"],
  "excludePaths": ["**/*.test.*", "**/*.spec.*"]
}
```

### How do I use RSOLV in a monorepo?

For monorepos, you can use path-based configuration:

```json
"repository": {
  "type": "monorepo",
  "rootPath": ".",
  "projects": [
    {
      "name": "frontend",
      "path": "packages/frontend",
      "language": "typescript"
    },
    {
      "name": "backend",
      "path": "packages/api",
      "language": "python"
    }
  ]
}
```

And set up RSOLV to scope its work based on the issue:

```json
"issue": {
  "scopeMapping": {
    "labels": {
      "frontend": ["packages/frontend"], 
      "backend": ["packages/api"]
    },
    "titlePatterns": {
      "^\\[FE\\]": ["packages/frontend"],
      "^\\[BE\\]": ["packages/api"]
    }
  }
}
```

### How can I enforce more rigorous testing for generated solutions?

Use the thorough quality setting and enhance with test requirements:

```json
"solution": {
  "quality": "thorough",
  "testRequirements": {
    "unitTestsRequired": true,
    "integrationTestsRequired": true,
    "minimumCoverage": 80,
    "testFramework": "jest"
  }
}
```

## Troubleshooting

### Common Configuration Errors

| Error | Solution |
|-------|----------|
| "Invalid configuration: Unknown field 'X'" | Check for typos in your configuration file |
| "Failed to parse configuration file" | Ensure your JSON is valid with proper syntax |
| "AI model 'X' not available" | Check that you're using a supported model |
| "Rate limit exceeded" | Reduce the frequency of RSOLV runs or contact us for a higher limit |

### Debugging Configuration Issues

To debug configuration issues, set the `RSOLV_LOG_LEVEL` environment variable to `debug`:

```yaml
- name: Run RSOLV
  uses: rsolv/autofix-action@v1
  with:
    api-key: ${{ secrets.RSOLV_API_KEY }}
  env:
    RSOLV_LOG_LEVEL: debug
```

You can also validate your configuration file in isolation:

```yaml
- name: Validate RSOLV Config
  uses: rsolv/validate-config@v1
  with:
    config-path: '.rsolv/config.json'
```

## Need More Help?

If you need further assistance with advanced configuration:

- Email us at support@rsolv.dev
- Open a discussion in our [GitHub repository](https://github.com/rsolv/early-access/discussions)
- Contact your Early Access Program representative for personalized support

---

This guide covers the most common advanced configuration scenarios. For custom enterprise configurations or specific integration needs not covered here, please contact our support team.