#!/bin/bash

# Memory-safe test runner for RSOLV-action
# Runs tests sequentially with memory limits

echo "🧪 RSOLV-action Memory-Safe Test Runner"
echo "========================================"

# Run tests file by file with memory limit
TEST_FILES=$(find src -name "*.test.ts" -o -name "*.test.js" | sort)
TOTAL=$(echo "$TEST_FILES" | wc -l)
PASSED=0
FAILED=0

for TEST_FILE in $TEST_FILES; do
  CURRENT=$((PASSED + FAILED + 1))
  echo -n "[$CURRENT/$TOTAL] Testing $(basename $TEST_FILE)... "
  
  if NODE_OPTIONS="--max-old-space-size=512" \
     NODE_ENV=test \
     USE_LOCAL_PATTERNS=true \
     npx vitest run "$TEST_FILE" --no-coverage --reporter=dot 2>/dev/null; then
    echo "✓"
    PASSED=$((PASSED + 1))
  else
    echo "✗"
    FAILED=$((FAILED + 1))
  fi
done

echo ""
echo "Results: $PASSED passed, $FAILED failed ($(echo "scale=1; $PASSED * 100 / $TOTAL" | bc)% pass rate)"
