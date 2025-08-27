#!/bin/bash

# Memory-safe test runner with increased heap and optimized configuration
# This script addresses memory exhaustion issues when running the full test suite

echo "================================================"
echo "Memory-Safe Test Runner"
echo "================================================"
echo
echo "Configuration:"
echo "- Node heap size: 4GB"
echo "- Process isolation: Enabled (forks)"
echo "- Concurrency: 1 test file at a time"
echo "- Test isolation: Full"
echo "================================================"
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to run tests with memory monitoring
run_with_memory_check() {
  local test_pattern=$1
  local test_name=$2
  
  echo -e "${YELLOW}Running: $test_name${NC}"
  echo "Pattern: $test_pattern"
  
  # Run with increased heap and memory config
  # Note: We pass the pattern directly without quotes to allow glob expansion
  NODE_OPTIONS="--max-old-space-size=4096 --expose-gc" \
    npx vitest run $test_pattern \
    --config vitest.config.memory.ts \
    --reporter=default \
    --no-coverage 2>&1 | tee /tmp/test-output.log
  
  local exit_code=$?
  
  # Check for OOM in output
  if grep -q "JavaScript heap out of memory" /tmp/test-output.log; then
    echo -e "${RED}❌ Memory exhaustion detected!${NC}"
    return 1
  elif [ $exit_code -eq 0 ]; then
    echo -e "${GREEN}✓ Tests passed${NC}"
    return 0
  else
    echo -e "${RED}✗ Tests failed (exit code: $exit_code)${NC}"
    return $exit_code
  fi
}

# Parse command line arguments
MODE="${1:-all}"

case "$MODE" in
  "security")
    echo "Running security tests with memory safety..."
    run_with_memory_check "src/security/**/*.test.ts" "Security Tests"
    ;;
  
  "ai")
    echo "Running AI tests with memory safety..."
    run_with_memory_check "src/ai/**/*.test.ts" "AI Tests"
    ;;
  
  "integration")
    echo "Running integration tests with memory safety..."
    run_with_memory_check "tests/integration/**/*.test.ts" "Integration Tests"
    ;;
  
  "all")
    echo "Running ALL tests with memory safety..."
    echo "(This will take longer but should not exhaust memory)"
    echo
    
    # Run test groups sequentially with cleanup between
    FAILED_GROUPS=()
    
    # Group 1: Unit tests (usually lightweight)
    echo -e "\n${YELLOW}[Group 1/5] Unit Tests${NC}"
    if ! run_with_memory_check "src/utils/**/*.test.ts src/config/**/*.test.ts" "Unit Tests"; then
      FAILED_GROUPS+=("Unit Tests")
    fi
    
    # Force garbage collection between groups (if Node was started with --expose-gc)
    echo "Cleaning up memory between groups..."
    node -e "if (global.gc) { global.gc(); console.log('GC performed'); }"
    sleep 2
    
    # Group 2: Integration tests
    echo -e "\n${YELLOW}[Group 2/5] Integration Tests${NC}"
    if ! run_with_memory_check "tests/integration/**/*.test.ts" "Integration Tests"; then
      FAILED_GROUPS+=("Integration Tests")
    fi
    
    node -e "if (global.gc) { global.gc(); console.log('GC performed'); }"
    sleep 2
    
    # Group 3: Mode tests
    echo -e "\n${YELLOW}[Group 3/5] Mode Tests${NC}"
    if ! run_with_memory_check "src/modes/**/*.test.ts" "Mode Tests"; then
      FAILED_GROUPS+=("Mode Tests")
    fi
    
    node -e "if (global.gc) { global.gc(); console.log('GC performed'); }"
    sleep 2
    
    # Group 4: AI tests (memory intensive)
    echo -e "\n${YELLOW}[Group 4/5] AI Tests${NC}"
    if ! run_with_memory_check "src/ai/**/*.test.ts" "AI Tests"; then
      FAILED_GROUPS+=("AI Tests")
    fi
    
    node -e "if (global.gc) { global.gc(); console.log('GC performed'); }"
    sleep 2
    
    # Group 5: Security tests (most memory intensive)
    echo -e "\n${YELLOW}[Group 5/5] Security Tests${NC}"
    if ! run_with_memory_check "src/security/**/*.test.ts" "Security Tests"; then
      FAILED_GROUPS+=("Security Tests")
    fi
    
    # Summary
    echo
    echo "================================================"
    echo "Test Suite Complete"
    echo "================================================"
    
    if [ ${#FAILED_GROUPS[@]} -eq 0 ]; then
      echo -e "${GREEN}✓ All test groups passed!${NC}"
      exit 0
    else
      echo -e "${RED}✗ Failed groups:${NC}"
      for group in "${FAILED_GROUPS[@]}"; do
        echo "  - $group"
      done
      exit 1
    fi
    ;;
  
  "profile")
    echo "Running tests with memory profiling..."
    echo "This will generate memory snapshots in .memory-profiles/"
    
    mkdir -p .memory-profiles
    
    NODE_OPTIONS="--max-old-space-size=4096 --expose-gc --heap-prof" \
      npx vitest run "$2" \
      --config vitest.config.memory.ts \
      --reporter=verbose
    
    echo "Memory profiles saved to .memory-profiles/"
    echo "Analyze with: node --prof-process .memory-profiles/*.log"
    ;;
  
  *)
    echo "Usage: $0 [all|security|ai|integration|profile] [test-pattern]"
    echo
    echo "Modes:"
    echo "  all         - Run all tests with memory safety (default)"
    echo "  security    - Run only security tests"
    echo "  ai          - Run only AI tests"  
    echo "  integration - Run only integration tests"
    echo "  profile     - Run with memory profiling enabled"
    echo
    echo "Examples:"
    echo "  $0                    # Run all tests"
    echo "  $0 security           # Run security tests only"
    echo "  $0 profile 'src/ai/**/*.test.ts'  # Profile AI tests"
    exit 1
    ;;
esac