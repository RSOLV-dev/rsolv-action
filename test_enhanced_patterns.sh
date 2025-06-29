#!/bin/bash

echo "🔍 Testing Enhanced Pattern Format API"
echo ""

# First, ensure the server is running
echo "1️⃣ Checking if server is running..."
if ! curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/health | grep -q "200"; then
    echo "   ❌ Server not running on port 4000"
    echo "   Please start the server with: mix phx.server"
    exit 1
fi
echo "   ✅ Server is running"

echo ""
echo "2️⃣ Testing standard format (should not have AST data):"
curl -s -X GET 'http://localhost:4000/api/v1/patterns?language=javascript&format=standard' \
  -H 'Accept: application/json' | \
  jq '.patterns[0] | {id: .id, has_ast_rules: (has("ast_rules")), has_context_rules: (has("context_rules"))}'

echo ""
echo "3️⃣ Testing enhanced format (should have AST data):"
curl -s -X GET 'http://localhost:4000/api/v1/patterns?language=javascript&format=enhanced' \
  -H 'Accept: application/json' | \
  jq '.patterns[0] | {
    id: .id, 
    has_ast_rules: (has("ast_rules") and .ast_rules != null), 
    has_context_rules: (has("context_rules") and .context_rules != null),
    has_confidence_rules: (has("confidence_rules") and .confidence_rules != null),
    has_min_confidence: (has("min_confidence") and .min_confidence != null)
  }'

echo ""
echo "4️⃣ Checking AST rule details for js-eval-user-input:"
curl -s -X GET 'http://localhost:4000/api/v1/patterns?language=javascript&format=enhanced' \
  -H 'Accept: application/json' | \
  jq '.patterns[] | select(.id == "js-eval-user-input") | {
    id: .id,
    ast_rules: .ast_rules | keys,
    context_rules: .context_rules | keys,
    min_confidence: .min_confidence
  }'

echo ""
echo "5️⃣ Testing regex serialization:"
curl -s -X GET 'http://localhost:4000/api/v1/patterns?language=javascript&format=enhanced' \
  -H 'Accept: application/json' | \
  jq '.patterns[0].context_rules.exclude_paths[0] | if type == "object" and .__type == "regex" then "✅ Regex properly serialized" else "❌ Regex not serialized correctly" end'

echo ""
echo "✅ Test complete!"