#!/bin/bash

API_KEY="staging_test_F344F8491174D8F27943D0DB12A4A13D"
API_URL="https://api.rsolv-staging.com/api/v1/vulnerabilities/validate"

echo "=== Simple Cache Load Test ==="
echo "Testing cache performance with repeated requests..."
echo ""

# First, prime the cache with a few requests
echo "Phase 1: Priming cache (5 unique patterns)..."

for i in {1..5}; do
  curl -s -X POST "$API_URL" \
    -H "X-API-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{
      \"vulnerabilities\": [{
        \"type\": \"sql-injection\",
        \"locations\": [{
          \"file_path\": \"app/test${i}.js\",
          \"line\": 10,
          \"is_primary\": true
        }],
        \"code\": \"db.query('SELECT * FROM users WHERE id = ' + userId)\"
      }],
      \"files\": {
        \"app/test${i}.js\": {
          \"content\": \"// test file\",
          \"hash\": \"sha256:consistent${i}\"
        }
      },
      \"repository\": \"staging-test-org/cache-test\"
    }" > /dev/null 2>&1
  echo -n "."
done
echo " Done!"

# Now test cache hits with the same requests
echo ""
echo "Phase 2: Testing cache hits (100 requests, 5 patterns repeated)..."

HITS=0
MISSES=0

for run in {1..20}; do
  for i in {1..5}; do
    RESPONSE=$(curl -s -X POST "$API_URL" \
      -H "X-API-Key: $API_KEY" \
      -H "Content-Type: application/json" \
      -d "{
        \"vulnerabilities\": [{
          \"type\": \"sql-injection\",
          \"locations\": [{
            \"file_path\": \"app/test${i}.js\",
            \"line\": 10,
            \"is_primary\": true
          }],
          \"code\": \"db.query('SELECT * FROM users WHERE id = ' + userId)\"
        }],
        \"files\": {
          \"app/test${i}.js\": {
            \"content\": \"// test file\",
            \"hash\": \"sha256:consistent${i}\"
          }
        },
        \"repository\": \"staging-test-org/cache-test\"
      }" 2>/dev/null)
    
    if echo "$RESPONSE" | grep -q '"fromCache":true'; then
      HITS=$((HITS + 1))
      echo -n "H"
    else
      MISSES=$((MISSES + 1))
      echo -n "M"
    fi
    
    # Small delay
    sleep 0.1
  done
  echo -n " [Run $run/20]"
done

echo ""
echo ""
echo "=== Results ==="
TOTAL=$((HITS + MISSES))
echo "Total requests: $TOTAL"
echo "Cache hits: $HITS"
echo "Cache misses: $MISSES"

if [ $TOTAL -gt 0 ]; then
  HIT_RATE=$((HITS * 100 / TOTAL))
  echo "Cache hit rate: ${HIT_RATE}%"
  
  if [ $HIT_RATE -gt 80 ]; then
    echo ""
    echo "✅ SUCCESS: Cache is working excellently!"
    echo "   - Hit rate: ${HIT_RATE}%"
    echo "   - System is ready for production"
  elif [ $HIT_RATE -gt 60 ]; then
    echo ""
    echo "✅ GOOD: Cache is working well"
    echo "   - Hit rate: ${HIT_RATE}%"
    echo "   - System is ready for production"
  else
    echo ""
    echo "⚠️  WARNING: Low cache hit rate"
    echo "   - Hit rate: ${HIT_RATE}%"
    echo "   - Investigation recommended"
  fi
fi

# Check final cache stats
echo ""
echo "=== System Cache Stats ==="
FINAL=$(curl -s -X POST "$API_URL" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerabilities": [{
      "type": "sql-injection",
      "locations": [{
        "file_path": "app/test1.js",
        "line": 10,
        "is_primary": true
      }],
      "code": "db.query(\"SELECT * FROM users WHERE id = \" + userId)"
    }],
    "files": {
      "app/test1.js": {
        "content": "// test file",
        "hash": "sha256:consistent1"
      }
    },
    "repository": "staging-test-org/cache-test"
  }' 2>/dev/null)

if echo "$FINAL" | jq -e '.cache_stats' > /dev/null 2>&1; then
  echo "$FINAL" | jq '.cache_stats'
fi

echo ""
echo "=== Load Test Complete ==="