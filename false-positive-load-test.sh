#!/bin/bash

API_KEY="staging_test_F344F8491174D8F27943D0DB12A4A13D"
API_URL="https://api.rsolv-staging.com/api/v1/vulnerabilities/validate"

echo "=== False Positive Cache Load Test ==="
echo "Testing cache with known false positive patterns..."
echo ""

# Clear any existing cache first
echo "Clearing cache..."
./clear-staging-cache.sh > /dev/null 2>&1

echo "Phase 1: Priming cache with false positives (5 patterns)..."

# These are all SAFE patterns that should be marked as false positives
for i in {1..5}; do
  curl -s -X POST "$API_URL" \
    -H "X-API-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{
      \"vulnerabilities\": [{
        \"type\": \"sql-injection\",
        \"locations\": [{
          \"file_path\": \"app/safe${i}.js\",
          \"line\": 10,
          \"is_primary\": true
        }],
        \"code\": \"db.query('SELECT * FROM users WHERE id = \$1', [userId])\"
      }],
      \"files\": {
        \"app/safe${i}.js\": {
          \"content\": \"// Using parameterized query - safe\",
          \"hash\": \"sha256:safe${i}\"
        }
      },
      \"repository\": \"staging-test-org/fp-test\"
    }" > /dev/null 2>&1
  echo -n "."
done
echo " Done!"

# Test XSS false positives too
echo "Adding XSS false positives..."
for i in {1..5}; do
  curl -s -X POST "$API_URL" \
    -H "X-API-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{
      \"vulnerabilities\": [{
        \"type\": \"xss\",
        \"locations\": [{
          \"file_path\": \"app/xss-safe${i}.js\",
          \"line\": 20,
          \"is_primary\": true
        }],
        \"code\": \"element.textContent = userInput\"
      }],
      \"files\": {
        \"app/xss-safe${i}.js\": {
          \"content\": \"// Using textContent - safe from XSS\",
          \"hash\": \"sha256:xss-safe${i}\"
        }
      },
      \"repository\": \"staging-test-org/fp-test\"
    }" > /dev/null 2>&1
  echo -n "."
done
echo " Done!"

echo ""
echo "Phase 2: Testing cache hits (100 requests for cached false positives)..."

HITS=0
MISSES=0

for run in {1..10}; do
  # Test SQL injection false positives
  for i in {1..5}; do
    RESPONSE=$(curl -s -X POST "$API_URL" \
      -H "X-API-Key: $API_KEY" \
      -H "Content-Type: application/json" \
      -d "{
        \"vulnerabilities\": [{
          \"type\": \"sql-injection\",
          \"locations\": [{
            \"file_path\": \"app/safe${i}.js\",
            \"line\": 10,
            \"is_primary\": true
          }],
          \"code\": \"db.query('SELECT * FROM users WHERE id = \$1', [userId])\"
        }],
        \"files\": {
          \"app/safe${i}.js\": {
            \"content\": \"// Using parameterized query - safe\",
            \"hash\": \"sha256:safe${i}\"
          }
        },
        \"repository\": \"staging-test-org/fp-test\"
      }" 2>/dev/null)
    
    if echo "$RESPONSE" | grep -q '"fromCache":true'; then
      HITS=$((HITS + 1))
      echo -n "H"
    else
      MISSES=$((MISSES + 1))
      echo -n "M"
    fi
  done
  
  # Test XSS false positives
  for i in {1..5}; do
    RESPONSE=$(curl -s -X POST "$API_URL" \
      -H "X-API-Key: $API_KEY" \
      -H "Content-Type: application/json" \
      -d "{
        \"vulnerabilities\": [{
          \"type\": \"xss\",
          \"locations\": [{
            \"file_path\": \"app/xss-safe${i}.js\",
            \"line\": 20,
            \"is_primary\": true
          }],
          \"code\": \"element.textContent = userInput\"
        }],
        \"files\": {
          \"app/xss-safe${i}.js\": {
            \"content\": \"// Using textContent - safe from XSS\",
            \"hash\": \"sha256:xss-safe${i}\"
          }
        },
        \"repository\": \"staging-test-org/fp-test\"
      }" 2>/dev/null)
    
    if echo "$RESPONSE" | grep -q '"fromCache":true'; then
      HITS=$((HITS + 1))
      echo -n "H"
    else
      MISSES=$((MISSES + 1))
      echo -n "M"
    fi
  done
  
  echo " [Run $run/10]"
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
    echo "✅ SUCCESS: False positive cache is working excellently!"
    echo "   - Hit rate: ${HIT_RATE}%"
    echo "   - System is ready for production"
  elif [ $HIT_RATE -gt 60 ]; then
    echo ""
    echo "✅ GOOD: False positive cache is working well"
    echo "   - Hit rate: ${HIT_RATE}%"
    echo "   - System is ready for production"
  else
    echo ""
    echo "⚠️  WARNING: Low cache hit rate"
    echo "   - Hit rate: ${HIT_RATE}%"
    echo "   - Investigation recommended"
  fi
fi

# Check system stats
echo ""
echo "=== System Cache Stats ==="
FINAL=$(curl -s -X POST "$API_URL" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerabilities": [{
      "type": "sql-injection",
      "locations": [{
        "file_path": "app/safe1.js",
        "line": 10,
        "is_primary": true
      }],
      "code": "db.query(\"SELECT * FROM users WHERE id = $1\", [userId])"
    }],
    "files": {
      "app/safe1.js": {
        "content": "// Using parameterized query - safe",
        "hash": "sha256:safe1"
      }
    },
    "repository": "staging-test-org/fp-test"
  }' 2>/dev/null)

if echo "$FINAL" | jq -e '.cache_stats' > /dev/null 2>&1; then
  echo "$FINAL" | jq '.cache_stats'
  echo ""
  echo "Sample cached result:"
  echo "$FINAL" | jq '.validated[0] | {isValid, fromCache, reason}'
fi

echo ""
echo "=== False Positive Cache Test Complete ==="