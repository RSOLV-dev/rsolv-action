#!/bin/bash

# Test known false positive patterns that should be cached
# These are common patterns that look like vulnerabilities but aren't

API_KEY="staging_test_F344F8491174D8F27943D0DB12A4A13D"
API_URL="https://api.rsolv-staging.com/api/v1/vulnerabilities/validate"

echo "=== Testing Known False Positives ==="
echo "These should be cached as false positives (isValid: false)"
echo ""

# Test 1: SQL in test fixtures
echo "Test 1: SQL injection in test fixture"
RESULT=$(curl -s -X POST "$API_URL" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerabilities": [{
      "type": "sql-injection",
      "locations": [{
        "file_path": "test/fixtures/users.test.js",
        "line": 15,
        "is_primary": true
      }],
      "code": "db.query(\"SELECT * FROM users WHERE id = 1\")"
    }],
    "files": {
      "test/fixtures/users.test.js": {
        "content": "// Test fixture\nconst testUser = db.query(\"SELECT * FROM users WHERE id = 1\");",
        "hash": "sha256:fixture1"
      }
    },
    "repository": "staging-test-org/false-positive-test"
  }')

echo "$RESULT" | jq -r '.validated[0] | "Result: isValid=\(.isValid), reason=\(.reason)"'
echo "$RESULT" | jq -r '.cache_stats | "Cache: hits=\(.cache_hits), misses=\(.cache_misses)"'
echo ""

# Test 2: XSS in React dangerouslySetInnerHTML with sanitization
echo "Test 2: XSS in React with sanitization"
RESULT=$(curl -s -X POST "$API_URL" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerabilities": [{
      "type": "xss",
      "locations": [{
        "file_path": "components/Article.jsx",
        "line": 42,
        "is_primary": true
      }],
      "code": "dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(content)}}"
    }],
    "files": {
      "components/Article.jsx": {
        "content": "import DOMPurify from \"dompurify\";\n<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(content)}} />",
        "hash": "sha256:react1"
      }
    },
    "repository": "staging-test-org/false-positive-test"
  }')

echo "$RESULT" | jq -r '.validated[0] | "Result: isValid=\(.isValid), reason=\(.reason)"'
echo "$RESULT" | jq -r '.cache_stats | "Cache: hits=\(.cache_hits), misses=\(.cache_misses)"'
echo ""

# Test 3: Command injection in build script
echo "Test 3: Command injection in build script"
RESULT=$(curl -s -X POST "$API_URL" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerabilities": [{
      "type": "command-injection",
      "locations": [{
        "file_path": "scripts/build.js",
        "line": 10,
        "is_primary": true
      }],
      "code": "exec(\"npm run build:prod\")"
    }],
    "files": {
      "scripts/build.js": {
        "content": "// Build script\nconst { exec } = require(\"child_process\");\nexec(\"npm run build:prod\");",
        "hash": "sha256:build1"
      }
    },
    "repository": "staging-test-org/false-positive-test"
  }')

echo "$RESULT" | jq -r '.validated[0] | "Result: isValid=\(.isValid), reason=\(.reason)"'
echo "$RESULT" | jq -r '.cache_stats | "Cache: hits=\(.cache_hits), misses=\(.cache_misses)"'
echo ""

# Test 4: Path traversal in config file
echo "Test 4: Path traversal in static config"
RESULT=$(curl -s -X POST "$API_URL" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerabilities": [{
      "type": "path-traversal",
      "locations": [{
        "file_path": "config/paths.js",
        "line": 5,
        "is_primary": true
      }],
      "code": "path.join(__dirname, \"../assets\")"
    }],
    "files": {
      "config/paths.js": {
        "content": "// Static path configuration\nconst assetPath = path.join(__dirname, \"../assets\");",
        "hash": "sha256:paths1"
      }
    },
    "repository": "staging-test-org/false-positive-test"
  }')

echo "$RESULT" | jq -r '.validated[0] | "Result: isValid=\(.isValid), reason=\(.reason)"'
echo "$RESULT" | jq -r '.cache_stats | "Cache: hits=\(.cache_hits), misses=\(.cache_misses)"'
echo ""

echo "=== Re-running all tests to verify cache hits ==="
echo "All should now show fromCache: true"
echo ""

# Re-run test 1 to verify cache
echo "Re-test 1: SQL injection (should be cached)"
RESULT=$(curl -s -X POST "$API_URL" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerabilities": [{
      "type": "sql-injection",
      "locations": [{
        "file_path": "test/fixtures/users.test.js",
        "line": 15,
        "is_primary": true
      }],
      "code": "db.query(\"SELECT * FROM users WHERE id = 1\")"
    }],
    "files": {
      "test/fixtures/users.test.js": {
        "content": "// Test fixture\nconst testUser = db.query(\"SELECT * FROM users WHERE id = 1\");",
        "hash": "sha256:fixture1"
      }
    },
    "repository": "staging-test-org/false-positive-test"
  }')

echo "$RESULT" | jq -r '.validated[0] | "fromCache: \(.fromCache), cacheHitType: \(.cacheHitType)"'
echo "$RESULT" | jq -r '.cache_stats | "Hit rate: \(.hit_rate)%"'

echo ""
echo "Test complete! False positives should be properly cached."