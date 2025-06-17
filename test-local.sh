#!/bin/bash
# Local testing script for RSOLV-action using act
# Requires: brew install act

echo "🧪 Testing RSOLV-action locally with act..."

# Test with staging API
echo "Testing against staging environment..."
act -s RSOLV_API_KEY="${RSOLV_STAGING_API_KEY:-test-key}" \
    -s GITHUB_TOKEN="${GITHUB_TOKEN}" \
    --var RSOLV_API_URL="https://api.rsolv-staging.com" \
    -W .github/workflows/rsolv-dogfood.yml \
    -j rsolv-automation \
    --container-architecture linux/amd64

# Test specific issue
if [ -n "$1" ]; then
    echo "Testing with specific issue #$1..."
    act workflow_dispatch \
        -s RSOLV_API_KEY="${RSOLV_STAGING_API_KEY:-test-key}" \
        -s GITHUB_TOKEN="${GITHUB_TOKEN}" \
        --var RSOLV_API_URL="https://api.rsolv-staging.com" \
        -W .github/workflows/manual-trigger.yml \
        --input issue_number="$1" \
        --container-architecture linux/amd64
fi