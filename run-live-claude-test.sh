#!/bin/bash
# Script to run the live Claude Code integration test

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

# Help message
show_help() {
  echo "Usage: $0 [OPTIONS]"
  echo
  echo "Run live integration tests for the Claude Code adapter"
  echo
  echo "Options:"
  echo "  -h, --help        Show this help message"
  echo "  -t, --timeout N   Set timeout in seconds (default: 300)"
  echo "  -v, --verify      Only verify test setup without running it"
  echo "  -s, --skip-check  Skip the Claude CLI availability check"
  echo
  echo "Examples:"
  echo "  $0                 Run with default settings (5 minute timeout)"
  echo "  $0 --timeout 600   Run with 10 minute timeout"
  echo "  $0 --verify        Only verify test is properly set up"
  echo
}

# Default values
TIMEOUT=300
VERIFY_ONLY=false
SKIP_CHECK=false

# Parse arguments
while [[ "$#" -gt 0 ]]; do
  case $1 in
    -h|--help) show_help; exit 0 ;;
    -t|--timeout) TIMEOUT="$2"; shift ;;
    -v|--verify) VERIFY_ONLY=true ;;
    -s|--skip-check) SKIP_CHECK=true ;;
    *) print_red "Unknown option: $1"; show_help; exit 1 ;;
  esac
  shift
done

# Script directory
SCRIPT_DIR="$(dirname "$0")"
cd "$SCRIPT_DIR" || exit 1

# If verify only, run verify script
if [ "$VERIFY_ONLY" = true ]; then
  if [ -f "$SCRIPT_DIR/verify-claude-test.sh" ]; then
    bash "$SCRIPT_DIR/verify-claude-test.sh"
    exit $?
  else
    print_red "❌ Verification script not found"
    exit 1
  fi
fi

# Check if we have an API key
if [ -z "$ANTHROPIC_API_KEY" ]; then
  print_red "❌ ANTHROPIC_API_KEY environment variable not set"
  print_yellow "Please set it with: export ANTHROPIC_API_KEY=your_key"
  exit 1
fi

# Check if claude is installed
if [ "$SKIP_CHECK" = false ]; then
  if ! command -v claude &> /dev/null; then
    print_red "❌ Claude CLI not found"
    print_yellow "Install it with: npm install -g @anthropic-ai/claude-code"
    print_yellow "Or run with --skip-check to bypass this verification"
    exit 1
  fi
fi

# Create test data directory if it doesn't exist
mkdir -p "$SCRIPT_DIR/test-data/live-claude"

# Run the test with timeout
print_blue "🧪 Running live Claude Code integration test (timeout: ${TIMEOUT}s)"

# Use timeout command with the specified timeout
timeout --foreground "${TIMEOUT}s" bun run live-claude-code-test.js
RESULT=$?

# Check exit code from timeout
if [ $RESULT -eq 124 ]; then
  print_red "❌ Test timed out after ${TIMEOUT} seconds"
  print_yellow "Try again with a longer timeout: $0 --timeout 600"
  exit 1
elif [ $RESULT -eq 0 ]; then
  print_green "✅ Live Claude Code integration test completed successfully"
else
  print_red "❌ Live Claude Code integration test failed (exit code: $RESULT)"
  exit 1
fi