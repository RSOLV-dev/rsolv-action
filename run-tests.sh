#!/bin/bash

# Unified test runner with memory safety and proper reporting
# Usage: ./run-tests.sh [options]
#   Options:
#     --memory-safe  Run with memory constraints (default in CI)
#     --live-api     Run live API tests
#     --e2e          Include E2E tests
#     --coverage     Generate coverage report
#     --json         Output JSON report
#     --watch        Run in watch mode

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Load .env file if it exists
if [ -f .env ]; then
  export $(cat .env | grep -v '^#' | xargs)
  echo "✓ Loaded environment variables from .env"
fi

# Initialize exit code
TEST_EXIT_CODE=0

echo -e "${GREEN}🧪 RSOLV-Action Test Suite${NC}"
echo "================================"

# Parse arguments
MEMORY_SAFE=""
LIVE_API=""
RUN_E2E=""
COVERAGE=""
JSON_OUTPUT=""
WATCH_MODE=""
EXTRA_ARGS=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --memory-safe)
      MEMORY_SAFE="TEST_MEMORY_SAFE=true"
      echo "✓ Memory-safe mode enabled"
      shift
      ;;
    --live-api)
      LIVE_API="TEST_LIVE_API=true"
      echo "✓ Live API tests enabled"
      shift
      ;;
    --e2e)
      RUN_E2E="RUN_E2E=true"
      echo "✓ E2E tests included"
      shift
      ;;
    --coverage)
      COVERAGE="--coverage"
      echo "✓ Coverage reporting enabled"
      shift
      ;;
    --json)
      JSON_OUTPUT="TEST_REPORTER=json TEST_OUTPUT_FILE=test-report.json"
      EXTRA_ARGS="--reporter=json --outputFile=test-report.json"
      echo "✓ JSON output to test-report.json"
      shift
      ;;
    --watch)
      WATCH_MODE="--watch"
      echo "✓ Watch mode enabled"
      shift
      ;;
    --shard=*)
      SHARD_SPEC="${1#*=}"
      EXTRA_ARGS="$EXTRA_ARGS --shard=$SHARD_SPEC"
      echo "✓ Running shard $SHARD_SPEC"
      shift
      ;;
    --reporter=*)
      REPORTER="${1#*=}"
      EXTRA_ARGS="$EXTRA_ARGS --reporter=$REPORTER"
      echo "✓ Using reporter: $REPORTER"
      shift
      ;;
    --outputFile=*)
      OUTPUT_FILE="${1#*=}"
      EXTRA_ARGS="$EXTRA_ARGS --outputFile=$OUTPUT_FILE"
      echo "✓ Output file: $OUTPUT_FILE"
      shift
      ;;
    *)
      echo -e "${YELLOW}Unknown option: $1${NC}"
      shift
      ;;
  esac
done

# Default to memory-safe in CI or if system has less than 8GB RAM
if [[ -z "$MEMORY_SAFE" ]]; then
  if [[ "$CI" == "true" ]]; then
    MEMORY_SAFE="TEST_MEMORY_SAFE=true"
    echo "✓ CI detected - using memory-safe mode"
  else
    # Check available memory (works on Linux and macOS)
    if command -v free &> /dev/null; then
      # Linux
      TOTAL_MEM=$(free -m | awk 'NR==2{print $2}')
    elif command -v sysctl &> /dev/null; then
      # macOS
      TOTAL_MEM=$(($(sysctl -n hw.memsize) / 1024 / 1024))
    else
      TOTAL_MEM=8192 # Default assumption
    fi
    
    if [[ $TOTAL_MEM -lt 8192 ]]; then
      MEMORY_SAFE="TEST_MEMORY_SAFE=true"
      echo -e "${YELLOW}⚠ Less than 8GB RAM detected - using memory-safe mode${NC}"
    fi
  fi
fi

# Set Node.js memory limit based on mode
if [[ -n "$MEMORY_SAFE" ]]; then
  # Use 6.5GB - isolation:false didn't reduce memory enough
  # Shard 14 still hits 4061MB with 4GB heap
  export NODE_OPTIONS="--max-old-space-size=6656"
  echo "✓ Node.js memory limit set to 6.5GB (memory-safe mode)"
else
  export NODE_OPTIONS="--max-old-space-size=8192"
  echo "✓ Node.js memory limit set to 8GB"
fi

# Build the command
if [[ -n "$MEMORY_SAFE" ]]; then
  # Use sharding for memory-safe mode
  # 16 shards - balance between execution time and memory isolation
  TOTAL_SHARDS=16
  echo "✓ Using sharded execution ($TOTAL_SHARDS shards)"

  # Create temporary directory for shard reports
  SHARD_DIR=".vitest-shards"
  mkdir -p $SHARD_DIR
  rm -f $SHARD_DIR/*.json

  # Run shards sequentially (1 at a time)
  # This prevents memory accumulation issues
  for i in $(seq 1 $TOTAL_SHARDS); do
    echo ""
    echo -e "${GREEN}Running shard $i/$TOTAL_SHARDS...${NC}"

    if [[ -n "$JSON_OUTPUT" ]]; then
      SHARD_CMD="$MEMORY_SAFE $LIVE_API $RUN_E2E bun x vitest run --shard=$i/$TOTAL_SHARDS --reporter=json --outputFile=$SHARD_DIR/shard-$i.json --passWithNoTests $COVERAGE"
    else
      SHARD_CMD="$MEMORY_SAFE $LIVE_API $RUN_E2E bun x vitest run --shard=$i/$TOTAL_SHARDS --passWithNoTests $COVERAGE"
    fi

    # Run shard and check exit code
    eval $SHARD_CMD
    SHARD_EXIT_CODE=$?

    if [[ $SHARD_EXIT_CODE -ne 0 ]]; then
      TEST_EXIT_CODE=$SHARD_EXIT_CODE
    fi

    echo -e "${GREEN}✓ Shard $i/$TOTAL_SHARDS complete${NC}"
  done
  
  # Merge JSON reports if needed
  if [[ -n "$JSON_OUTPUT" ]] && [[ -f "$SHARD_DIR/shard-1.json" ]]; then
    echo ""
    echo "Merging shard reports..."
    node merge-shard-results.cjs

    # Check actual test failures from merged report, not shard exit codes
    # Vitest exits with code 1 for pending tests, but we only want to fail on actual failures
    if [[ -f "test-report.json" ]]; then
      FAILED_TESTS=$(cat test-report.json | jq -r '.numFailedTests // 0')
      if [[ "$FAILED_TESTS" -eq 0 ]]; then
        TEST_EXIT_CODE=0
      else
        TEST_EXIT_CODE=1
      fi
    fi
  fi
else
  # Regular single run
  CMD="$MEMORY_SAFE $LIVE_API $RUN_E2E $JSON_OUTPUT bun x vitest run --passWithNoTests $COVERAGE $WATCH_MODE $EXTRA_ARGS"
  echo ""
  echo "Running command:"
  echo -e "${YELLOW}$CMD${NC}"
  echo ""
  eval $CMD
  TEST_EXIT_CODE=$?

  # Check actual test failures from report, not vitest exit code
  # Vitest exits with code 1 for pending tests, but we only want to fail on actual failures
  if [[ -n "$JSON_OUTPUT" ]] && [[ -f "test-report.json" ]]; then
    FAILED_TESTS=$(cat test-report.json | jq -r '.numFailedTests // 0')
    if [[ "$FAILED_TESTS" -eq 0 ]]; then
      TEST_EXIT_CODE=0
    else
      TEST_EXIT_CODE=1
    fi
  fi
fi

# Report results
echo ""
if [[ $TEST_EXIT_CODE -eq 0 ]]; then
  echo -e "${GREEN}✅ All tests passed!${NC}"
else
  echo -e "${RED}❌ Some tests failed${NC}"
  
  # If JSON output, parse and show summary
  if [[ -n "$JSON_OUTPUT" ]] && [[ -f "test-report.json" ]]; then
    echo ""
    echo "Test Summary:"
    cat test-report.json | jq '{
      total: .numTotalTests,
      passed: .numPassedTests,
      failed: .numFailedTests,
      skipped: (.numPendingTests + .numTodoTests),
      passRate: (
        ((.numPassedTests + .numFailedTests) as $runnable |
        if $runnable > 0 then
          ((.numPassedTests / $runnable) * 100 | tostring + "%")
        else
          "100%"
        end)
      )
    }' 2>/dev/null || echo "(Unable to parse JSON report)"
  fi
fi

exit $TEST_EXIT_CODE