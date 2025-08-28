#!/bin/bash

echo "Complete Test Failure Summary"
echo "=============================="
echo ""

FAILING_FILES=(
  "src/scanner/__tests__/ast-validator-live-api.test.ts"
  "src/security/analyzers/__tests__/elixir-ast-analyzer-encryption.test.ts"
  "src/security/analyzers/__tests__/elixir-ast-analyzer-patterns.test.ts"
  "src/security/analyzers/__tests__/elixir-ast-analyzer.test.ts"
  "src/security/analyzers/__tests__/fallback-strategy.test.ts"
  "src/security/pattern-api-client.test.ts"
  "src/security/pattern-api-client-tier-removal.test.ts"
  "src/security/pattern-regex-reconstruction.test.ts"
  "src/security/__tests__/ast-pattern-interpreter.test.ts"
  "src/__tests__/ai/anthropic-vending.test.ts"
)

TOTAL_TESTS=0
TOTAL_PASSED=0
TOTAL_FAILED=0

for FILE in "${FAILING_FILES[@]}"; do
  if [ -f "$FILE" ]; then
    echo "$(basename $FILE):"
    
    # Run with timeout to prevent hanging
    RESULT=$(timeout 10s NODE_OPTIONS="--max-old-space-size=512" NODE_ENV=test USE_LOCAL_PATTERNS=true \
      npx vitest run "$FILE" --reporter=json --no-coverage 2>/dev/null)
    
    if [ $? -eq 124 ]; then
      echo "  ⚠️  Timed out (likely memory issue)"
    elif [ -z "$RESULT" ]; then
      echo "  ⚠️  Failed to run"
    else
      # Parse JSON with jq
      STATS=$(echo "$RESULT" | jq -r '. | "  Tests: \(.numTotalTests), Passed: \(.numPassedTests), Failed: \(.numFailedTests)"')
      echo "$STATS"
      
      # Add to totals
      TESTS=$(echo "$RESULT" | jq -r '.numTotalTests')
      PASSED=$(echo "$RESULT" | jq -r '.numPassedTests')
      FAILED=$(echo "$RESULT" | jq -r '.numFailedTests')
      
      TOTAL_TESTS=$((TOTAL_TESTS + TESTS))
      TOTAL_PASSED=$((TOTAL_PASSED + PASSED))
      TOTAL_FAILED=$((TOTAL_FAILED + FAILED))
    fi
  fi
done

echo ""
echo "Summary:"
echo "--------"
echo "Total in failing files: $TOTAL_TESTS tests"
echo "Passed: $TOTAL_PASSED"
echo "Failed: $TOTAL_FAILED"
