#!/bin/bash

# Monitor cache performance in staging
# Usage: ./monitor-cache-performance.sh

API_KEY="staging_test_F344F8491174D8F27943D0DB12A4A13D"
API_URL="https://api.rsolv-staging.com/api/v1/vulnerabilities/validate"

echo "=== RSOLV Cache Performance Monitor ==="
echo "Testing cache hit rates with various scenarios..."
echo ""

# Test 1: Multiple requests for same vulnerability (should get high hit rate)
echo "Test 1: Repeated requests for same vulnerability"
echo "------------------------------------------------"
for i in {1..5}; do
  echo -n "Request $i: "
  curl -s -X POST "$API_URL" \
    -H "X-API-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d '{
      "vulnerabilities": [{
        "type": "sql-injection",
        "locations": [{
          "file_path": "monitor/test1.js",
          "line": 42,
          "is_primary": true
        }],
        "code": "db.query(sql)"
      }],
      "files": {
        "monitor/test1.js": {
          "content": "const sql = input; db.query(sql);",
          "hash": "sha256:monitor1"
        }
      },
      "repository": "staging-test-org/monitor"
    }' | jq -r '.cache_stats | "Hits: \(.cache_hits), Misses: \(.cache_misses), Hit Rate: \(.hit_rate)%"'
done

echo ""
echo "Test 2: Different vulnerabilities (testing cache growth)"
echo "--------------------------------------------------------"
for i in {1..3}; do
  echo -n "New vulnerability $i: "
  curl -s -X POST "$API_URL" \
    -H "X-API-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{
      \"vulnerabilities\": [{
        \"type\": \"sql-injection\",
        \"locations\": [{
          \"file_path\": \"monitor/test$i.js\",
          \"line\": $((100 + i)),
          \"is_primary\": true
        }],
        \"code\": \"db.query(userInput$i)\"
      }],
      \"files\": {
        \"monitor/test$i.js\": {
          \"content\": \"// Test $i\ndb.query(userInput$i);\",
          \"hash\": \"sha256:monitor$i$i$i\"
        }
      },
      \"repository\": \"staging-test-org/monitor\"
    }" | jq -r '.cache_stats | "Total Cached: \(.total_cached_entries), TTL: \(.avg_ttl_remaining) days"'
done

echo ""
echo "Test 3: File modification (testing invalidation)"
echo "------------------------------------------------"
echo -n "Original file: "
curl -s -X POST "$API_URL" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerabilities": [{
      "type": "xss",
      "locations": [{
        "file_path": "monitor/xss.js",
        "line": 10,
        "is_primary": true
      }],
      "code": "innerHTML = userContent"
    }],
    "files": {
      "monitor/xss.js": {
        "content": "element.innerHTML = userContent;",
        "hash": "sha256:xss_original"
      }
    },
    "repository": "staging-test-org/monitor"
  }' | jq -r '.validated[0] | "fromCache: \(.fromCache)"'

echo -n "Same request (should hit cache): "
curl -s -X POST "$API_URL" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerabilities": [{
      "type": "xss",
      "locations": [{
        "file_path": "monitor/xss.js",
        "line": 10,
        "is_primary": true
      }],
      "code": "innerHTML = userContent"
    }],
    "files": {
      "monitor/xss.js": {
        "content": "element.innerHTML = userContent;",
        "hash": "sha256:xss_original"
      }
    },
    "repository": "staging-test-org/monitor"
  }' | jq -r '.validated[0] | "fromCache: \(.fromCache), cacheHitType: \(.cacheHitType)"'

echo -n "Modified file (should miss cache): "
curl -s -X POST "$API_URL" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerabilities": [{
      "type": "xss",
      "locations": [{
        "file_path": "monitor/xss.js",
        "line": 10,
        "is_primary": true
      }],
      "code": "innerHTML = userContent"
    }],
    "files": {
      "monitor/xss.js": {
        "content": "// MODIFIED\nelement.innerHTML = userContent;",
        "hash": "sha256:xss_modified"
      }
    },
    "repository": "staging-test-org/monitor"
  }' | jq -r '.validated[0] | "fromCache: \(.fromCache)"'

echo ""
echo "=== Cache Performance Summary ==="
curl -s -X POST "$API_URL" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerabilities": [{
      "type": "test",
      "locations": [{
        "file_path": "summary.js",
        "line": 1,
        "is_primary": true
      }],
      "code": "test"
    }],
    "files": {
      "summary.js": {
        "content": "test",
        "hash": "sha256:summary"
      }
    },
    "repository": "staging-test-org/monitor"
  }' | jq '.cache_stats'

echo ""
echo "Cache monitoring complete!"