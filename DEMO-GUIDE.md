# RSOLV Demo Environment Guide

This guide provides detailed instructions for using the RSOLV Demo Environment created for Day 5.

## Overview

The RSOLV Demo Environment is an interactive CLI tool that allows you to manually exercise all components of the RSOLV system. It provides a guided workflow through the entire process of issue analysis, solution generation, PR creation, and feedback collection.

## Getting Started

### Prerequisites

- Bun runtime
- GitHub token (for accessing GitHub issues)
- Anthropic API key (or other supported AI provider key)

### Running the Demo

```bash
# Set up environment variables (optional)
export GITHUB_TOKEN=your_github_token
export ANTHROPIC_API_KEY=your_anthropic_api_key
export AI_PROVIDER=anthropic # or openrouter, ollama

# Run the demo
cd RSOLV-action
bun run demo-env
```

If you don't set the environment variables, the demo will prompt you for them when needed.

## Main Menu

The demo presents a menu of available actions based on your current state in the workflow:

```
📋 Available Actions:
1. Get Issue (GitHub or Manual)
2. Analyze Issue
3. Generate Solution
4. Create PR
5. Simulate Feedback
6. View Feedback Statistics
7. Test Prompt Enhancement
8. Exit Demo
```

Options will be enabled or disabled based on your progress through the workflow.

## Workflow Steps

### 1. Get Issue Context

You have two options for getting an issue:

- **GitHub Issue URL**: Enter a real GitHub issue URL (e.g., https://github.com/owner/repo/issues/123)
- **Manual Input**: Enter issue details manually for demo purposes

This step establishes the context for the rest of the workflow.

### 2. Analyze Issue

Once you have an issue context, you can analyze it with AI. You'll be prompted to:

1. Select an AI provider (anthropic, openrouter, ollama)
2. Provide the API key if not already set in environment variables

The analysis will determine:
- Issue complexity (low, medium, high)
- Estimated time to fix (in minutes)
- Related files that may need modification
- Suggested approach

### 3. Generate Solution

After analysis, you can generate an AI solution for the issue. You'll have the option to:

- Use standard solution generation
- Use feedback-enhanced solution generation (if feedback exists)

The feedback enhancement demonstrates the feedback loop system by incorporating patterns from previous feedback into the prompt.

### 4. Create PR

This step simulates creating a pull request with the generated solution. In a real environment, this would:

1. Create a new branch
2. Apply the code changes
3. Open a pull request with a detailed description
4. Link the PR to the original issue

In the demo environment, this generates a mock PR number if GitHub access is not available.

### 5. Simulate Feedback

Once a PR (real or mock) is created, you can simulate expert feedback:

1. Enter reviewer information
2. Select feedback type (comment, review, edit, approve, reject)
3. Choose sentiment (positive, negative, neutral)
4. Provide feedback content

This feedback is stored and will influence future prompt enhancements.

### 6. View Feedback Statistics

View aggregate statistics on the feedback collected, including:

- Total count by sentiment (positive, negative, neutral)
- Breakdown by feedback type
- Breakdown by action taken
- Timeline of feedback over time

### 7. Test Prompt Enhancement

See how collected feedback influences future prompts:

1. A base prompt is created using the current issue
2. Feedback patterns are extracted from historical feedback
3. The prompt is enhanced with these patterns
4. You can view both the original and enhanced prompts

This demonstrates how the system learns from expert feedback over time.

## Data Persistence

The demo environment saves state between sessions:

- Issue context
- Analysis results
- PR information
- Feedback data

This allows you to exit and resume the demo without losing progress.

## Example Workflow

A typical demo workflow:

1. Get Issue: Either from GitHub or manual input
2. Analyze Issue: Generate complexity assessment
3. Generate Solution: Create code changes to fix the issue
4. Create PR: Simulate PR creation with the solution
5. Simulate Feedback: Add expert review feedback
6. Generate Another Solution: See how feedback influences the next solution
7. View Statistics: See the impact of collected feedback

## Troubleshooting

- If you encounter API authentication errors, check your API keys
- The `demo-data` directory contains saved state and feedback data
- Delete `demo-data/demo-state.json` to start a fresh session

## Next Steps

After exploring the demo environment, consider:

1. Reviewing the implementation in `demo-environment.ts`
2. Examining the feedback system in `src/feedback/`
3. Contributing improvements to the demo or main RSOLV action