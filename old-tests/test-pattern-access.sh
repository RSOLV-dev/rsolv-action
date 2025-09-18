#!/bin/bash

# Test pattern API access with authentication

API_KEY="rsolv_test_demo123456789"
API_URL="https://api.rsolv.dev/api/v1/patterns"

echo "Testing pattern API access..."
echo "============================="

# Test each language
for lang in javascript python ruby java elixir php; do
  echo -e "\nFetching $lang patterns..."
  curl -s -H "Authorization: Bearer $API_KEY" "$API_URL?language=$lang" | \
    jq -r '.metadata | "Language: \(.language), Count: \(.count), Access: \(.access_level)"'
done

echo -e "\n\nTotal pattern counts by language:"
echo "================================="

total=0
for lang in javascript python ruby java elixir php; do
  count=$(curl -s -H "Authorization: Bearer $API_KEY" "$API_URL?language=$lang" | jq -r '.patterns | length')
  echo "$lang: $count patterns"
  total=$((total + count))
done

echo -e "\nTotal patterns accessible: $total"

# Check without API key
echo -e "\n\nWithout API key (demo patterns only):"
echo "====================================="

demo_total=0
for lang in javascript python ruby java elixir php; do
  count=$(curl -s "$API_URL?language=$lang" | jq -r '.patterns | length')
  echo "$lang: $count patterns"
  demo_total=$((demo_total + count))
done

echo -e "\nTotal demo patterns: $demo_total"