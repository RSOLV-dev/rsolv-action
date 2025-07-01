#\!/bin/bash
echo "🔍 Testing Pattern Loading via API"
echo "========================================"

# Test 1: Get patterns via API
echo -e "\n1. Getting patterns through API:"
PATTERNS=$(curl -s http://localhost:4002/api/v1/patterns/python -H "X-API-Key: rsolv_test_abc123")
PATTERN_COUNT=$(echo "$PATTERNS" | jq '.patterns | length')
echo "   API returned $PATTERN_COUNT patterns"

# Test 2: Check AST analysis with detailed response
echo -e "\n2. Testing AST analysis:"
RESPONSE=$(curl -s -X POST http://localhost:4002/api/v1/ast/analyze \
  -H "X-API-Key: rsolv_test_abc123" \
  -H "X-Encryption-Key: $(openssl rand -base64 32)" \
  -H "Content-Type: application/json" \
  -d '{
    "files": [{
      "path": "test.py",
      "content": "query = \"SELECT * FROM users WHERE id = \" + user_id",
      "language": "python"
    }]
  }')

echo "$RESPONSE" | jq '.'

# Test 3: Check server logs
echo -e "\n3. Recent server logs:"
docker logs rsolv-api-rsolv-api-no-volumes-1 2>&1 | tail -20 | grep -E "(PatternAdapter|AnalysisService|patterns|Loaded)"

