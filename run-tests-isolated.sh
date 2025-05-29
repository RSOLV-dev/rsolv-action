#!/bin/bash

# Run each test file in isolation to work around Bun mock pollution issues
# This script helps identify which tests are actually failing

echo "Running tests in isolation..."
echo "=============================="

total_pass=0
total_fail=0
failed_files=()

# Find all test files
test_files=$(find tests src -name "*.test.ts" -type f | sort)

for test_file in $test_files; do
    echo -n "Testing $test_file... "
    
    # Run test and capture exit code
    if bun test "$test_file" --timeout 30000 > /tmp/test_output.txt 2>&1; then
        # Count pass/fail from output
        pass_count=$(grep -o "pass" /tmp/test_output.txt | wc -l | tr -d ' ')
        echo "✓ ($pass_count tests)"
        total_pass=$((total_pass + pass_count))
    else
        # Test failed, extract failure count
        fail_count=$(grep -o "fail" /tmp/test_output.txt | wc -l | tr -d ' ')
        echo "✗ ($fail_count failures)"
        total_fail=$((total_fail + fail_count))
        failed_files+=("$test_file")
        
        # Show error details for debugging
        echo "  Error details:"
        grep -A 5 "error:\|fail)" /tmp/test_output.txt | sed 's/^/    /'
    fi
done

echo ""
echo "=============================="
echo "Summary:"
echo "  Total passed: $total_pass"
echo "  Total failed: $total_fail"
echo ""

if [ ${#failed_files[@]} -gt 0 ]; then
    echo "Failed files:"
    for file in "${failed_files[@]}"; do
        echo "  - $file"
    done
fi