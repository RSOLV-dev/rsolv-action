#!/bin/bash
# Run tests in isolation to avoid mock pollution issues
# This is a temporary workaround for Bun's test isolation problems

echo "Running tests in isolation mode..."
echo "This avoids mock pollution issues between test files"
echo ""

FAILED=0
PASSED=0
TOTAL=0

# Find all test files
TEST_FILES=$(find . -name "*.test.ts" -not -path "./node_modules/*" -not -path "./archived/*")

for test_file in $TEST_FILES; do
    TOTAL=$((TOTAL + 1))
    echo -n "Running $test_file... "
    
    # Run the test and capture output
    if bun test "$test_file" > /tmp/test-output.txt 2>&1; then
        PASSED=$((PASSED + 1))
        echo "✅ PASSED"
    else
        FAILED=$((FAILED + 1))
        echo "❌ FAILED"
        echo "Error output:"
        cat /tmp/test-output.txt | grep -E "(fail|error|Error)" | head -5
        echo ""
    fi
done

echo ""
echo "========================================="
echo "Test Summary:"
echo "Total test files: $TOTAL"
echo "Passed: $PASSED"
echo "Failed: $FAILED"
echo "========================================="

if [ $FAILED -eq 0 ]; then
    echo "✅ All tests passed in isolation!"
    exit 0
else
    echo "❌ Some tests failed"
    exit 1
fi