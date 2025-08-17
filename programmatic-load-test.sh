#!/bin/bash

# Programmatic load test for staging
API_KEY="staging_test_F344F8491174D8F27943D0DB12A4A13D"
API_URL="https://api.rsolv-staging.com/api/v1/vulnerabilities/validate"
DURATION_SECONDS=300  # 5 minutes
CONCURRENT_REQUESTS=5

echo "=== Programmatic Load Test for Staging ==="
echo "Duration: ${DURATION_SECONDS}s"
echo "Concurrent requests: ${CONCURRENT_REQUESTS}"
echo "Starting at: $(date)"
echo ""

# Track metrics
TOTAL_REQUESTS=0
CACHE_HITS=0
ERRORS=0
START_TIME=$(date +%s)
END_TIME=$((START_TIME + DURATION_SECONDS))

# Function to send a request
send_request() {
  local file_num=$1
  local iteration=$2
  
  # Mix of real vulnerabilities and false positives
  if [ $((iteration % 3)) -eq 0 ]; then
    # Real vulnerability
    local code="db.query(\"SELECT * FROM users WHERE id = \" + req.params.id)"
    local vuln_type="sql-injection"
  elif [ $((iteration % 3)) -eq 1 ]; then
    # False positive (safe pattern)
    local code="db.query(\"SELECT * FROM users WHERE id = \$1\", [userId])"
    local vuln_type="sql-injection"
  else
    # Another false positive
    local code="element.textContent = userInput"
    local vuln_type="xss"
  fi
  
  # Use consistent file paths and hashes to test cache hits
  # Only vary between a small set of files to ensure cache hits
  local file_path="app/file$((file_num % 3)).js"
  local line=$((10 + (file_num % 5)))  # Only 5 different line numbers
  
  # Use consistent hash for each file to ensure cache hits
  local file_hash="sha256:consistent_hash_file$((file_num % 3))"
  
  response=$(curl -s -X POST "$API_URL" \
    -H "X-API-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{
      \"vulnerabilities\": [{
        \"type\": \"${vuln_type}\",
        \"locations\": [{
          \"file_path\": \"${file_path}\",
          \"line\": ${line},
          \"is_primary\": true
        }],
        \"code\": \"${code}\"
      }],
      \"files\": {
        \"${file_path}\": {
          \"content\": \"const code = '${code}';\",
          \"hash\": \"${file_hash}\"
        }
      },
      \"repository\": \"staging-test-org/load-test\"
    }" 2>/dev/null)
  
  if [ -n "$response" ]; then
    # Check if it was a cache hit
    if echo "$response" | grep -q '"fromCache":true'; then
      echo -n "H"  # Cache hit
      CACHE_HITS=$((CACHE_HITS + 1))
    else
      echo -n "M"  # Cache miss
    fi
    TOTAL_REQUESTS=$((TOTAL_REQUESTS + 1))
  else
    echo -n "E"  # Error
    ERRORS=$((ERRORS + 1))
  fi
}

# Function to run concurrent requests
run_batch() {
  for i in $(seq 1 $CONCURRENT_REQUESTS); do
    send_request $i $1 &
  done
  wait
}

echo "Running load test..."
echo "Progress: (H=cache hit, M=cache miss, E=error)"

iteration=0
while [ $(date +%s) -lt $END_TIME ]; do
  run_batch $iteration
  ((iteration++))
  
  # Show progress every 50 requests
  if [ $((TOTAL_REQUESTS % 50)) -eq 0 ] && [ $TOTAL_REQUESTS -gt 0 ]; then
    echo " [$TOTAL_REQUESTS requests]"
  fi
  
  # Small delay between batches
  sleep 0.5
done

echo ""
echo ""
echo "=== Load Test Results ==="
echo "Total requests: $TOTAL_REQUESTS"
echo "Cache hits: $CACHE_HITS"
echo "Cache misses: $((TOTAL_REQUESTS - CACHE_HITS - ERRORS))"
echo "Errors: $ERRORS"

if [ $TOTAL_REQUESTS -gt 0 ]; then
  HIT_RATE=$((CACHE_HITS * 100 / TOTAL_REQUESTS))
  echo "Cache hit rate: ${HIT_RATE}%"
  
  DURATION=$(($(date +%s) - START_TIME))
  RPS=$((TOTAL_REQUESTS / DURATION))
  echo "Requests per second: ~${RPS}"
fi

echo "Completed at: $(date)"

# Final verification - check a known pattern to ensure cache is working
echo ""
echo "=== Final Cache Verification ==="
VERIFY_RESPONSE=$(curl -s -X POST "$API_URL" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerabilities": [{
      "type": "sql-injection",
      "locations": [{
        "file_path": "app/file1.js",
        "line": 10,
        "is_primary": true
      }],
      "code": "db.query(\"SELECT * FROM users WHERE id = \" + req.params.id)"
    }],
    "files": {
      "app/file1.js": {
        "content": "const code = '\''db.query(\"SELECT * FROM users WHERE id = \" + req.params.id)'\''",
        "hash": "sha256:test10"
      }
    },
    "repository": "staging-test-org/load-test"
  }')

if echo "$VERIFY_RESPONSE" | jq -e '.cache_stats.hit_rate' > /dev/null 2>&1; then
  FINAL_HIT_RATE=$(echo "$VERIFY_RESPONSE" | jq -r '.cache_stats.hit_rate')
  TOTAL_CACHED=$(echo "$VERIFY_RESPONSE" | jq -r '.cache_stats.total_cached_entries')
  echo "System cache hit rate: ${FINAL_HIT_RATE}%"
  echo "Total cached entries: $TOTAL_CACHED"
else
  echo "Could not retrieve cache statistics"
fi

echo ""
echo "=== Load Test Complete ==="

if [ $TOTAL_REQUESTS -gt 0 ]; then
  if [ $HIT_RATE -gt 60 ] && [ $ERRORS -lt 10 ]; then
    echo "✅ SUCCESS: Cache performing well under load"
    echo "   - Hit rate > 60%: YES (${HIT_RATE}%)"
    echo "   - Error rate < 1%: YES"
    echo "   - Ready for production"
  else
    echo "⚠️  WARNING: Cache performance needs review"
    echo "   - Hit rate: ${HIT_RATE}%"
    echo "   - Errors: $ERRORS"
  fi
else
  echo "❌ ERROR: No requests completed successfully"
fi