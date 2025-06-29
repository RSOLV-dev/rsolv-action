#!/bin/bash

echo "🔍 Testing Full Pattern Set with API Authentication"
echo ""

# First, let's create a test customer with API key if needed
echo "1️⃣ Setting up test customer with API key..."

# Check if we have a test customer
TEST_API_KEY="test-api-key-12345"
CUSTOMER_EMAIL="test@example.com"

# Create the test customer if needed
elixir -e '
alias RSOLV.Accounts

case Accounts.get_customer_by_email("test@example.com") do
  nil ->
    {:ok, customer} = Accounts.create_customer(%{
      email: "test@example.com",
      name: "Test Customer",
      company: "Test Company",
      api_key: "test-api-key-12345"
    })
    IO.puts("Created test customer with API key: #{customer.api_key}")
  
  customer ->
    IO.puts("Test customer already exists with API key: #{customer.api_key}")
end
' 2>/dev/null || echo "   Note: Run 'mix run create-test-customer.exs' to create test customer"

echo ""
echo "2️⃣ Testing full patterns with API key (JavaScript):"
curl -s -X GET 'http://localhost:4000/api/v1/patterns?language=javascript&format=enhanced' \
  -H 'Accept: application/json' \
  -H "Authorization: Bearer $TEST_API_KEY" | \
  jq '{
    metadata: .metadata,
    pattern_count: (.patterns | length),
    first_pattern: (.patterns[0] | {
      id: .id,
      has_ast_rules: (has("ast_rules") and .ast_rules != null),
      has_context_rules: (has("context_rules") and .context_rules != null)
    }),
    patterns_with_ast: [.patterns[] | select(.ast_rules != null) | .id] | length
  }'

echo ""
echo "3️⃣ Testing specific pattern with known AST enhancement (js-eval-user-input):"
curl -s -X GET 'http://localhost:4000/api/v1/patterns?language=javascript&format=enhanced' \
  -H 'Accept: application/json' \
  -H "Authorization: Bearer $TEST_API_KEY" | \
  jq '.patterns[] | select(.id == "js-eval-user-input") | {
    id: .id,
    name: .name,
    ast_rules: (.ast_rules | keys),
    context_rules: (.context_rules | keys),
    confidence_rules: (.confidence_rules | keys),
    min_confidence: .min_confidence
  }'

echo ""
echo "4️⃣ Testing regex serialization in context_rules:"
curl -s -X GET 'http://localhost:4000/api/v1/patterns?language=javascript&format=enhanced' \
  -H 'Accept: application/json' \
  -H "Authorization: Bearer $TEST_API_KEY" | \
  jq '.patterns[] | select(.context_rules.exclude_paths != null) | {
    id: .id,
    first_exclude_path: .context_rules.exclude_paths[0],
    is_serialized_regex: (.context_rules.exclude_paths[0] | type == "object" and has("__type"))
  } | select(.first_exclude_path != null)' | head -20

echo ""
echo "5️⃣ Testing other languages with enhanced format:"
for lang in python ruby java php elixir; do
  echo ""
  echo "   Language: $lang"
  curl -s -X GET "http://localhost:4000/api/v1/patterns?language=$lang&format=enhanced" \
    -H 'Accept: application/json' \
    -H "Authorization: Bearer $TEST_API_KEY" | \
    jq '{
      pattern_count: (.patterns | length),
      patterns_with_ast: [.patterns[] | select(.ast_rules != null) | .id] | length
    }'
done

echo ""
echo "6️⃣ Comparing standard vs enhanced format sizes:"
STANDARD_SIZE=$(curl -s -X GET 'http://localhost:4000/api/v1/patterns?language=javascript&format=standard' \
  -H "Authorization: Bearer $TEST_API_KEY" | wc -c)
ENHANCED_SIZE=$(curl -s -X GET 'http://localhost:4000/api/v1/patterns?language=javascript&format=enhanced' \
  -H "Authorization: Bearer $TEST_API_KEY" | wc -c)

echo "   Standard format size: $STANDARD_SIZE bytes"
echo "   Enhanced format size: $ENHANCED_SIZE bytes"
echo "   Size increase: $((ENHANCED_SIZE - STANDARD_SIZE)) bytes ($(( (ENHANCED_SIZE - STANDARD_SIZE) * 100 / STANDARD_SIZE ))%)"

echo ""
echo "✅ Full pattern test complete!"