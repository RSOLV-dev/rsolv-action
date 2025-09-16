#!/bin/bash
# Test RSOLV Vulnerability Validation API with correct format

set -euo pipefail

echo "========================================================="
echo "RSOLV Vulnerability Validation API Test (Correct Format)"
echo "========================================================="

# Configuration
STAGING_URL="https://rsolv-staging.com"
API_KEY="rsolv_Nc4KkUwhoEtkKC2vZvrM8bINAY4t258qh8cYoam9hxE"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo -e "${BLUE}Testing vulnerability validation with correct format...${NC}"

# Create test request with vulnerabilities array and files object
REQUEST_BODY=$(cat << 'EOF'
{
  "vulnerabilities": [
    {
      "filePath": "app.js",
      "type": "sql_injection",
      "severity": "high",
      "line": 6,
      "column": 19,
      "message": "SQL Injection vulnerability detected",
      "pattern": "sql_concat_user_input",
      "code": "const query = \"SELECT * FROM users WHERE id = \" + userId;"
    },
    {
      "filePath": "search.js",
      "type": "xss",
      "severity": "medium",
      "line": 3,
      "column": 5,
      "message": "Cross-site scripting vulnerability",
      "pattern": "xss_direct_response",
      "code": "res.send(`<h1>Search results for: ${searchTerm}</h1>`);"
    }
  ],
  "files": {
    "app.js": {
      "content": "const express = require('express');\nconst app = express();\n\napp.get('/user/:id', (req, res) => {\n    const userId = req.params.id;\n    const query = \"SELECT * FROM users WHERE id = \" + userId;\n    db.query(query, (err, results) => {\n        res.json(results);\n    });\n});"
    },
    "search.js": {
      "content": "app.get('/search', (req, res) => {\n    const searchTerm = req.query.q;\n    res.send(`<h1>Search results for: ${searchTerm}</h1>`);\n});"
    }
  }
}
EOF
)

echo "Sending validation request..."
echo ""

# Call the validation API
RESPONSE=$(curl -s -X POST "$STAGING_URL/api/v1/vulnerabilities/validate" \
    -H "X-Api-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d "$REQUEST_BODY")

echo "Response:"
echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"

# Check if validation was successful
if echo "$RESPONSE" | jq -e '.validated' > /dev/null 2>&1; then
    echo ""
    echo -e "${GREEN}✅ Vulnerability validation successful!${NC}"

    # Extract stats
    if echo "$RESPONSE" | jq -e '.stats' > /dev/null 2>&1; then
        echo ""
        echo "Validation Stats:"
        echo "$RESPONSE" | jq '.stats'
    fi

    # Show validated vulnerabilities
    if echo "$RESPONSE" | jq -e '.validated[]' > /dev/null 2>&1; then
        echo ""
        echo -e "${YELLOW}Validated vulnerabilities:${NC}"
        echo "$RESPONSE" | jq '.validated'
    fi
else
    echo ""
    ERROR_MSG=$(echo "$RESPONSE" | jq -r '.error // .errors.detail // "Unknown error"' 2>/dev/null)
    echo -e "${YELLOW}⚠️  Validation failed: $ERROR_MSG${NC}"
fi

echo ""
echo "========================================================="
echo -e "${GREEN}Test Complete${NC}"
echo "=========================================================">