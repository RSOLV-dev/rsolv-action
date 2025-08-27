#!/bin/bash

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "RSOLV-action Test Suite Overall State"
echo "Date: $(date)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Set environment
export RSOLV_API_KEY=${RSOLV_API_KEY:-staging-master-key-123}
export RSOLV_API_URL=${RSOLV_API_URL:-https://api.rsolv-staging.com}
export NODE_OPTIONS="--max-old-space-size=2048"

# Test directories
DIRS=(
    "src/github"
    "src/utils" 
    "src/credentials"
    "src/modes"
    "src/ai"
    "src/security"
    "src/scanner"
    "src/validation"
    "tests/integration"
    "tests/security"
    "test/unit"
)

TOTAL_FILES=0
TOTAL_PASSED_FILES=0
TOTAL_TESTS=0
TOTAL_PASSED_TESTS=0
TOTAL_FAILED_TESTS=0

echo "Testing by directory:"
echo "─────────────────────"

for dir in "${DIRS[@]}"; do
    if [ -d "$dir" ]; then
        echo -n "$dir: "
        
        # Run tests and capture output
        OUTPUT=$(timeout 45 npx vitest run "$dir" --no-coverage 2>&1 | tail -20)
        
        # Extract test counts
        FILES_LINE=$(echo "$OUTPUT" | grep "Test Files" | tail -1)
        TESTS_LINE=$(echo "$OUTPUT" | grep "Tests" | grep -v "Test Files" | tail -1)
        
        if [ ! -z "$FILES_LINE" ]; then
            # Parse file counts
            if echo "$FILES_LINE" | grep -q "passed"; then
                FILE_PASSED=$(echo "$FILES_LINE" | grep -oE "[0-9]+ passed" | grep -oE "[0-9]+")
                FILE_FAILED=$(echo "$FILES_LINE" | grep -oE "[0-9]+ failed" | grep -oE "[0-9]+")
                FILE_FAILED=${FILE_FAILED:-0}
                
                FILE_TOTAL=$((FILE_PASSED + FILE_FAILED))
                TOTAL_FILES=$((TOTAL_FILES + FILE_TOTAL))
                TOTAL_PASSED_FILES=$((TOTAL_PASSED_FILES + FILE_PASSED))
                
                # Parse test counts
                if [ ! -z "$TESTS_LINE" ]; then
                    TEST_PASSED=$(echo "$TESTS_LINE" | grep -oE "[0-9]+ passed" | grep -oE "[0-9]+")
                    TEST_FAILED=$(echo "$TESTS_LINE" | grep -oE "[0-9]+ failed" | grep -oE "[0-9]+")
                    TEST_FAILED=${TEST_FAILED:-0}
                    
                    TEST_TOTAL=$((TEST_PASSED + TEST_FAILED))
                    TOTAL_TESTS=$((TOTAL_TESTS + TEST_TOTAL))
                    TOTAL_PASSED_TESTS=$((TOTAL_PASSED_TESTS + TEST_PASSED))
                    TOTAL_FAILED_TESTS=$((TOTAL_FAILED_TESTS + TEST_FAILED))
                    
                    if [ $FILE_FAILED -eq 0 ]; then
                        echo "✅ $FILE_PASSED/$FILE_TOTAL files, $TEST_PASSED/$TEST_TOTAL tests"
                    else
                        echo "⚠️  $FILE_PASSED/$FILE_TOTAL files, $TEST_PASSED/$TEST_TOTAL tests"
                    fi
                else
                    echo "⚠️  $FILE_PASSED/$FILE_TOTAL files (test count unavailable)"
                fi
            else
                echo "❌ No passing tests found"
            fi
        else
            # Check for timeout or other issues
            if echo "$OUTPUT" | grep -q "heap out of memory"; then
                echo "💥 Out of memory"
            elif echo "$OUTPUT" | grep -q "No test files found"; then
                echo "⚠️  No test files"
            else
                echo "❓ Unable to run (timeout/error)"
            fi
        fi
    else
        echo "$dir: Directory not found"
    fi
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "OVERALL SUMMARY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test Files: $TOTAL_PASSED_FILES/$TOTAL_FILES passing ($([ $TOTAL_FILES -gt 0 ] && echo "scale=1; $TOTAL_PASSED_FILES * 100 / $TOTAL_FILES" | bc || echo 0)%)"
echo "Individual Tests: $TOTAL_PASSED_TESTS/$TOTAL_TESTS passing ($([ $TOTAL_TESTS -gt 0 ] && echo "scale=1; $TOTAL_PASSED_TESTS * 100 / $TOTAL_TESTS" | bc || echo 0)%)"
echo "Failed Tests: $TOTAL_FAILED_TESTS"
echo ""

# Historical comparison
echo "Historical Context:"
echo "───────────────────"
echo "Initial state: ~595/784 tests passing (75%)"
echo "Session high: ~88% pass rate"
echo "Current: $([ $TOTAL_TESTS -gt 0 ] && echo "scale=1; $TOTAL_PASSED_TESTS * 100 / $TOTAL_TESTS" | bc || echo 0)% pass rate"
echo ""

# Key issues
echo "Known Issues:"
echo "─────────────"
echo "• Memory exhaustion on full test runs"
echo "• Test isolation problems (some tests fail in batch but pass alone)"
echo "• Insufficient security patterns for some languages"
echo "• Mock setup issues with vi.mock in some files"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"