#!/bin/bash
# Script to run Claude Code end-to-end tests in Docker or locally

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

# Check if we have an API key
if [ -z "$ANTHROPIC_API_KEY" ]; then
  print_red "❌ ANTHROPIC_API_KEY environment variable not set"
  print_yellow "Please set it with: export ANTHROPIC_API_KEY=your_key"
  exit 1
fi

# Check if we should run in Docker
USE_DOCKER=false
if [ "$1" == "--docker" ]; then
  USE_DOCKER=true
fi

# Local test directory
TEST_DATA_DIR="./test-data"
mkdir -p "$TEST_DATA_DIR"

if [ "$USE_DOCKER" = true ]; then
  print_blue "🐳 Running Claude Code end-to-end test in Docker"
  
  # Build Docker image if needed
  if ! docker image ls | grep -q rsolv-action; then
    print_blue "Building Docker image..."
    docker build -t rsolv-action .
  fi
  
  # Run the test in Docker
  print_blue "Starting test in Docker container..."
  docker run --rm \
    -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
    -v "$(pwd)/test-data:/rsolv/test-data" \
    rsolv-action bun run test-claude-code.js
  
  print_green "✅ Test completed in Docker"
else
  print_blue "🧪 Running Claude Code end-to-end test locally"
  
  # Check if claude is installed
  if ! command -v claude &> /dev/null; then
    print_red "❌ Claude CLI not found"
    print_yellow "Install it with: npm install -g @anthropic-ai/claude-code"
    print_yellow "Or run with Docker: $0 --docker"
    exit 1
  fi
  
  # Run the test locally with increased timeout
  print_blue "Starting test..."
  bun run --timeout 300000 test-claude-code.js  # 5-minute timeout
  
  print_green "✅ Test completed locally"
fi

print_green "Test results are saved in the $TEST_DATA_DIR directory"