#!/bin/bash

# Count actual tests (not files)
echo "Counting individual tests..."

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Run each test file and count the actual tests
TEST_FILES=$(find src -name "*.test.ts" -o -name "*.test.js" | sort)

for TEST_FILE in $TEST_FILES; do
  # Run test and capture JSON output
  NODE_OPTIONS="--max-old-space-size=512" \
  NODE_ENV=test \
  USE_LOCAL_PATTERNS=true \
  npx vitest run "$TEST_FILE" \
    --no-coverage \
    --reporter=json \
    2>/dev/null > .test-output.json
  
  # Parse the JSON to count tests
  if [ -s .test-output.json ]; then
    # Count tests in this file
    FILE_TESTS=$(grep -o '"status":"pass"' .test-output.json 2>/dev/null | wc -l)
    FILE_FAILURES=$(grep -o '"status":"fail"' .test-output.json 2>/dev/null | wc -l)
    
    PASSED_TESTS=$((PASSED_TESTS + FILE_TESTS))
    FAILED_TESTS=$((FAILED_TESTS + FILE_FAILURES))
  fi
done

TOTAL_TESTS=$((PASSED_TESTS + FAILED_TESTS))

echo "Total tests: $TOTAL_TESTS"
echo "Passed: $PASSED_TESTS"
echo "Failed: $FAILED_TESTS"
if [ $TOTAL_TESTS -gt 0 ]; then
  PASS_RATE=$(echo "scale=1; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc)
  echo "Pass rate: ${PASS_RATE}%"
fi

rm -f .test-output.json
