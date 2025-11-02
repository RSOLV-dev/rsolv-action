#!/bin/bash
API_KEY="rsolv_xud6j-kCuMwsQ371QNBkQvTi5gmfZQ98FPXbmNmhMio"

echo "Testing validation endpoint..."
curl -k -X POST https://rsolv-staging.com/api/v1/vulnerabilities/validate \
  -H "X-Api-Key: $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"vulnerabilities":[{"filePath":"test.js","type":"xss","severity":"medium","line":42,"column":10,"message":"XSS","pattern":"xss_html","code":"const safe = escapeHtml(userInput);"}],"files":{"test.js":{"content":"const safe = escapeHtml(userInput);"}},"repository":"test-org/test-repo"}'

echo ""
echo "Test complete"