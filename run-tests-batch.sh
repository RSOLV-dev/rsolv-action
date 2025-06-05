#!/bin/bash
# Run tests in smaller batches for better visibility
BUN=~/.bun/bin/bun

echo "Running tests in batches..."
echo "=========================="

# Initialize counters
total_pass=0
total_fail=0
total_skip=0

# Run credential tests
echo -e "\n📁 Credential Tests"
output=$($BUN test src/credentials src/__tests__/credentials 2>&1 | tail -5)
echo "$output"

# Run AI tests  
echo -e "\n📁 AI Tests"
output=$($BUN test src/ai/__tests__ 2>&1 | tail -5)
echo "$output"

# Run security tests
echo -e "\n📁 Security Tests"
output=$($BUN test src/security/__tests__ 2>&1 | tail -5)
echo "$output"

# Run platform tests
echo -e "\n📁 Platform Tests"
output=$($BUN test src/platforms 2>&1 | tail -5)
echo "$output"

# Run feedback tests
echo -e "\n📁 Feedback Tests"
output=$($BUN test src/feedback/__tests__ 2>&1 | tail -5)
echo "$output"

# Run external API tests
echo -e "\n📁 External API Tests"
output=$($BUN test src/external/__tests__ 2>&1 | tail -5)
echo "$output"

# Run integration tests (excluding E2E)
echo -e "\n📁 Integration Tests"
output=$($BUN test tests/integration 2>&1 | tail -5)
echo "$output"

echo -e "\n✅ Test batches completed!"
echo "=========================="
echo "Note: E2E tests skipped (require real credentials)"