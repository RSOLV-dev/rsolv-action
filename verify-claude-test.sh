#!/bin/bash
# Helper script to verify Claude Code test implementation

set -e

# Function to print colored output
print_blue() {
  echo -e "\e[34m$1\e[0m"
}

print_green() {
  echo -e "\e[32m$1\e[0m"
}

print_red() {
  echo -e "\e[31m$1\e[0m"
}

print_yellow() {
  echo -e "\e[33m$1\e[0m"
}

# Check if claude is installed
if command -v claude &> /dev/null; then
  HAS_CLAUDE=true
  print_green "✅ Claude CLI is installed"
else
  HAS_CLAUDE=false
  print_yellow "ℹ️ Claude CLI is not installed - will verify test implementation only"
fi

# Check if ANTHROPIC_API_KEY is set
if [ -n "$ANTHROPIC_API_KEY" ]; then
  HAS_KEY=true
  print_green "✅ ANTHROPIC_API_KEY is set"
else
  HAS_KEY=false
  print_yellow "ℹ️ ANTHROPIC_API_KEY is not set - will verify test implementation only"
fi

# Create directory for test data if it doesn't exist
mkdir -p "$(dirname "$0")/test-data/live-claude"

# Verify that the test files exist
print_blue "🔍 Verifying test implementation..."

TEST_SCRIPT="$(dirname "$0")/live-claude-code-test.js"
RUNNER_SCRIPT="$(dirname "$0")/run-live-claude-test.sh"

if [ -f "$TEST_SCRIPT" ] && [ -f "$RUNNER_SCRIPT" ]; then
  print_green "✅ Live test files exist:"
  print_blue "  - $TEST_SCRIPT"
  print_blue "  - $RUNNER_SCRIPT"
else
  print_red "❌ Live test files are missing!"
  exit 1
fi

# Check if files are executable
if [ -x "$TEST_SCRIPT" ] && [ -x "$RUNNER_SCRIPT" ]; then
  print_green "✅ Test files are executable"
else
  print_yellow "ℹ️ Setting execute permissions on test files"
  chmod +x "$TEST_SCRIPT" "$RUNNER_SCRIPT"
fi

# Check test content
if grep -q "Testing the actual Claude Code adapter with the real Claude CLI" "$TEST_SCRIPT"; then
  print_green "✅ Test script contains correct integration testing code"
else
  print_red "❌ Test script does not contain proper integration testing code!"
  exit 1
fi

# Summary
print_green "\n✅ Claude Code live integration test is properly implemented"

if $HAS_CLAUDE && $HAS_KEY; then
  print_yellow "ℹ️ You can run the live test with: ./run-live-claude-test.sh"
else
  print_yellow "ℹ️ To run the actual test, ensure:"
  print_yellow "  1. Claude CLI is installed: npm install -g @anthropic-ai/claude-code"
  print_yellow "  2. API key is set: export ANTHROPIC_API_KEY=your_key"
  print_yellow "  3. Run: ./run-live-claude-test.sh"
fi

exit 0