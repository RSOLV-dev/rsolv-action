#!/bin/bash

# Test real vulnerabilities that should NOT be marked as false positives
# These are actual security issues that must be detected

API_KEY="staging_test_F344F8491174D8F27943D0DB12A4A13D"
API_URL="https://api.rsolv-staging.com/api/v1/vulnerabilities/validate"

echo "=== Testing Real Vulnerabilities ==="
echo "These should be validated as TRUE vulnerabilities (isValid: true)"
echo ""

# Test 1: SQL injection with user input
echo "Test 1: SQL injection with direct user input"
RESULT=$(curl -s -X POST "$API_URL" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerabilities": [{
      "type": "sql-injection",
      "locations": [{
        "file_path": "api/users.js",
        "line": 25,
        "is_primary": true
      }],
      "code": "db.query(\"SELECT * FROM users WHERE id = \" + req.params.userId)"
    }],
    "files": {
      "api/users.js": {
        "content": "app.get(\"/user/:userId\", (req, res) => {\n  const result = db.query(\"SELECT * FROM users WHERE id = \" + req.params.userId);\n  res.json(result);\n});",
        "hash": "sha256:realvuln1"
      }
    },
    "repository": "staging-test-org/real-vuln-test"
  }')

echo "$RESULT" | jq -r '.validated[0] | "Result: isValid=\(.isValid), reason=\(.reason)"'
IS_VALID=$(echo "$RESULT" | jq -r '.validated[0].isValid')
if [ "$IS_VALID" != "true" ]; then
  echo "❌ ERROR: Real SQL injection not detected!"
else
  echo "✅ Correctly identified as vulnerability"
fi
echo ""

# Test 2: XSS without sanitization
echo "Test 2: XSS with innerHTML and user input"
RESULT=$(curl -s -X POST "$API_URL" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerabilities": [{
      "type": "xss",
      "locations": [{
        "file_path": "public/comment.js",
        "line": 18,
        "is_primary": true
      }],
      "code": "element.innerHTML = userComment"
    }],
    "files": {
      "public/comment.js": {
        "content": "function displayComment(userComment) {\n  const element = document.getElementById(\"comments\");\n  element.innerHTML = userComment;\n}",
        "hash": "sha256:realvuln2"
      }
    },
    "repository": "staging-test-org/real-vuln-test"
  }')

echo "$RESULT" | jq -r '.validated[0] | "Result: isValid=\(.isValid), reason=\(.reason)"'
IS_VALID=$(echo "$RESULT" | jq -r '.validated[0].isValid')
if [ "$IS_VALID" != "true" ]; then
  echo "❌ ERROR: Real XSS vulnerability not detected!"
else
  echo "✅ Correctly identified as vulnerability"
fi
echo ""

# Test 3: Command injection with user input
echo "Test 3: Command injection with user-controlled input"
RESULT=$(curl -s -X POST "$API_URL" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerabilities": [{
      "type": "command-injection",
      "locations": [{
        "file_path": "api/converter.js",
        "line": 33,
        "is_primary": true
      }],
      "code": "exec(\"convert \" + req.body.filename + \" output.pdf\")"
    }],
    "files": {
      "api/converter.js": {
        "content": "app.post(\"/convert\", (req, res) => {\n  const { exec } = require(\"child_process\");\n  exec(\"convert \" + req.body.filename + \" output.pdf\");\n});",
        "hash": "sha256:realvuln3"
      }
    },
    "repository": "staging-test-org/real-vuln-test"
  }')

echo "$RESULT" | jq -r '.validated[0] | "Result: isValid=\(.isValid), reason=\(.reason)"'
IS_VALID=$(echo "$RESULT" | jq -r '.validated[0].isValid')
if [ "$IS_VALID" != "true" ]; then
  echo "❌ ERROR: Real command injection not detected!"
else
  echo "✅ Correctly identified as vulnerability"
fi
echo ""

# Test 4: Path traversal with user input
echo "Test 4: Path traversal with user-controlled path"
RESULT=$(curl -s -X POST "$API_URL" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerabilities": [{
      "type": "path-traversal",
      "locations": [{
        "file_path": "api/files.js",
        "line": 12,
        "is_primary": true
      }],
      "code": "fs.readFile(req.query.file)"
    }],
    "files": {
      "api/files.js": {
        "content": "app.get(\"/download\", (req, res) => {\n  const content = fs.readFile(req.query.file);\n  res.send(content);\n});",
        "hash": "sha256:realvuln4"
      }
    },
    "repository": "staging-test-org/real-vuln-test"
  }')

echo "$RESULT" | jq -r '.validated[0] | "Result: isValid=\(.isValid), reason=\(.reason)"'
IS_VALID=$(echo "$RESULT" | jq -r '.validated[0].isValid')
if [ "$IS_VALID" != "true" ]; then
  echo "❌ ERROR: Real path traversal not detected!"
else
  echo "✅ Correctly identified as vulnerability"
fi
echo ""

# Test 5: SSRF with user-controlled URL
echo "Test 5: SSRF with user input URL"
RESULT=$(curl -s -X POST "$API_URL" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerabilities": [{
      "type": "ssrf",
      "locations": [{
        "file_path": "api/proxy.js",
        "line": 8,
        "is_primary": true
      }],
      "code": "axios.get(req.body.url)"
    }],
    "files": {
      "api/proxy.js": {
        "content": "app.post(\"/fetch\", async (req, res) => {\n  const response = await axios.get(req.body.url);\n  res.json(response.data);\n});",
        "hash": "sha256:realvuln5"
      }
    },
    "repository": "staging-test-org/real-vuln-test"
  }')

echo "$RESULT" | jq -r '.validated[0] | "Result: isValid=\(.isValid), reason=\(.reason)"'
IS_VALID=$(echo "$RESULT" | jq -r '.validated[0].isValid')
if [ "$IS_VALID" != "true" ]; then
  echo "❌ ERROR: Real SSRF vulnerability not detected!"
else
  echo "✅ Correctly identified as vulnerability"
fi
echo ""

echo "=== Summary ==="
echo "All real vulnerabilities should be detected (isValid: true)"
echo "If any showed isValid: false, the cache may be incorrectly"
echo "marking real vulnerabilities as false positives - CRITICAL ISSUE!"