#!/bin/bash

# Run tests in shards with better memory management
# Usage: ./run-vitest-sharded.sh [num_shards]

NUM_SHARDS=${1:-8}
FAILED_COUNT=0
PASSED_COUNT=0
TOTAL_COUNT=0

echo "Running tests in $NUM_SHARDS shards with memory management..."
echo ""

# Clean up previous reports
rm -rf .vitest-reports
mkdir -p .vitest-reports

# Set environment variables for staging API
export RSOLV_API_KEY=${RSOLV_API_KEY:-staging-master-key-123}
export RSOLV_API_URL=${RSOLV_API_URL:-https://api.rsolv-staging.com}
export NODE_OPTIONS="--max-old-space-size=4096"

# Run each shard and collect results
for i in $(seq 1 $NUM_SHARDS); do
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "Running shard $i/$NUM_SHARDS..."
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  
  # Run the shard and capture output
  if timeout 120 npx vitest run --no-coverage --shard=$i/$NUM_SHARDS --reporter=json > .vitest-reports/shard-$i.json 2>&1; then
    echo "✅ Shard $i completed"
  else
    echo "⚠️ Shard $i had issues or timed out"
  fi
  
  # Try to extract stats from JSON output if valid
  if [ -f .vitest-reports/shard-$i.json ]; then
    # Extract test counts from JSON (basic parsing)
    SHARD_PASSED=$(grep -o '"passed":[0-9]*' .vitest-reports/shard-$i.json | tail -1 | cut -d: -f2)
    SHARD_FAILED=$(grep -o '"failed":[0-9]*' .vitest-reports/shard-$i.json | tail -1 | cut -d: -f2)
    
    if [ ! -z "$SHARD_PASSED" ]; then
      PASSED_COUNT=$((PASSED_COUNT + SHARD_PASSED))
    fi
    if [ ! -z "$SHARD_FAILED" ]; then
      FAILED_COUNT=$((FAILED_COUNT + SHARD_FAILED))
    fi
  fi
  
  echo ""
done

TOTAL_COUNT=$((PASSED_COUNT + FAILED_COUNT))

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "FINAL TEST SUMMARY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Total Tests: $TOTAL_COUNT"
echo "Passed: $PASSED_COUNT ($([ $TOTAL_COUNT -gt 0 ] && echo "scale=1; $PASSED_COUNT * 100 / $TOTAL_COUNT" | bc || echo 0)%)"
echo "Failed: $FAILED_COUNT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ $FAILED_COUNT -eq 0 ] && [ $TOTAL_COUNT -gt 0 ]; then
  echo "✅ All tests passed!"
  exit 0
else
  echo "❌ Some tests failed"
  exit 1
fi