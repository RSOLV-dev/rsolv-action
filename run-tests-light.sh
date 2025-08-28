#!/bin/bash

# Run tests file by file to minimize memory usage
# This script identifies failing tests without consuming excessive memory

echo "Running lightweight test scan..."

# Find all test files
TEST_FILES=$(find src -name "*.test.ts" -o -name "*.test.js" | sort)
TOTAL_FILES=$(echo "$TEST_FILES" | wc -l)
FAILED_FILES=""
PASSED_COUNT=0
FAILED_COUNT=0

echo "Found $TOTAL_FILES test files"
echo "---"

# Run each test file individually
for TEST_FILE in $TEST_FILES; do
  # Run test with minimal memory footprint
  NODE_ENV=test npx vitest run "$TEST_FILE" --no-coverage --reporter=json 2>/dev/null > .test-result.json
  
  # Check if test passed
  if [ $? -eq 0 ]; then
    PASSED_COUNT=$((PASSED_COUNT + 1))
    echo "✓ $TEST_FILE"
  else
    FAILED_COUNT=$((FAILED_COUNT + 1))
    echo "✗ $TEST_FILE"
    FAILED_FILES="$FAILED_FILES\n  $TEST_FILE"
  fi
done

echo "---"
echo "Summary:"
echo "  Passed: $PASSED_COUNT files"
echo "  Failed: $FAILED_COUNT files"

if [ $FAILED_COUNT -gt 0 ]; then
  echo ""
  echo "Failed test files:"
  echo -e "$FAILED_FILES"
  exit 1
fi

echo ""
echo "All tests passing! 🎉"
exit 0