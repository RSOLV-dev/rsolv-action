#!/bin/bash

# Test the full access API key to verify pattern counts

API_KEY="rsolv_test_full_access_no_quota_2025"
API_URL="https://api.rsolv.dev/api/v1/patterns"

echo "Testing Full Access API Key"
echo "=========================="
echo

# Test each language
languages=("javascript" "python" "ruby" "java" "elixir" "php")
total_patterns=0

for lang in "${languages[@]}"; do
  echo "Fetching $lang patterns..."
  response=$(curl -s -H "Authorization: Bearer $API_KEY" "$API_URL?language=$lang")
  
  # Extract count from metadata
  count=$(echo "$response" | jq -r '.metadata.count // 0')
  access_level=$(echo "$response" | jq -r '.metadata.access_level // "unknown"')
  
  echo "  Count: $count"
  echo "  Access Level: $access_level"
  
  # Count actual patterns in array
  actual_count=$(echo "$response" | jq '.patterns | length')
  echo "  Actual patterns in response: $actual_count"
  
  if [ "$count" -ne "$actual_count" ]; then
    echo "  WARNING: Metadata count doesn't match actual pattern count!"
  fi
  
  total_patterns=$((total_patterns + actual_count))
  echo
done

echo "Total patterns accessible: $total_patterns"
echo

# Compare with demo access
echo "Comparing with Demo Access (no API key)"
echo "======================================"
demo_total=0

for lang in "${languages[@]}"; do
  response=$(curl -s "$API_URL?language=$lang")
  count=$(echo "$response" | jq '.patterns | length')
  echo "$lang: $count demo patterns"
  demo_total=$((demo_total + count))
done

echo
echo "Total demo patterns: $demo_total"
echo "Additional patterns with API key: $((total_patterns - demo_total))"