#!/bin/bash
# End-to-end test script for Claude Code with real repository

# Check if ANTHROPIC_API_KEY is set
if [ -z "$ANTHROPIC_API_KEY" ]; then
  echo "❌ Error: ANTHROPIC_API_KEY not set."
  echo "Please set it with: export ANTHROPIC_API_KEY=your_key_here"
  exit 1
fi

# Create directories if they don't exist
mkdir -p e2e-tests/test-repos
mkdir -p e2e-tests/results

# Run the test
echo "🚀 Running end-to-end test for Claude Code with real repository..."
bun run e2e-tests/claude-code-real-repo.js

# Check the exit code
if [ $? -eq 0 ]; then
  echo "✅ Test completed successfully"
else
  echo "❌ Test failed"
  exit 1
fi

# Print summary
if [ -f "e2e-tests/results/comparison.json" ]; then
  echo "📊 Test Results Summary:"
  echo "========================"
  cat e2e-tests/results/comparison.json | jq '.'
else
  echo "⚠️ No comparison results found"
fi

echo "📄 Full results available in e2e-tests/results/"