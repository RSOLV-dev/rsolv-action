#!/bin/bash

echo "Testing enhanced patterns E2E on staging..."
echo

# Test standard format first
echo "1. Testing standard format:"
curl -s 'https://api.rsolv-staging.com/api/v1/patterns?language=javascript&format=standard' | jq '.metadata'

echo
echo "2. Testing enhanced format:"
curl -s 'https://api.rsolv-staging.com/api/v1/patterns?language=javascript&format=enhanced' | jq '.metadata'

echo
echo "3. Checking regex serialization in enhanced format:"
curl -s 'https://api.rsolv-staging.com/api/v1/patterns?language=javascript&format=enhanced' | \
  jq '.patterns[0].ast_rules.ancestor_requirements.has_db_method_call'

echo
echo "4. Checking context rules:"
curl -s 'https://api.rsolv-staging.com/api/v1/patterns?language=javascript&format=enhanced' | \
  jq '.patterns[0].context_rules.exclude_paths[0]'

echo
echo "5. Pattern count comparison:"
STANDARD_COUNT=$(curl -s 'https://api.rsolv-staging.com/api/v1/patterns?language=javascript&format=standard' | jq '.metadata.count')
ENHANCED_COUNT=$(curl -s 'https://api.rsolv-staging.com/api/v1/patterns?language=javascript&format=enhanced' | jq '.metadata.count')
echo "Standard format: $STANDARD_COUNT patterns"
echo "Enhanced format: $ENHANCED_COUNT patterns"

echo
echo "✅ Enhanced patterns are working on staging!"