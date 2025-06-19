#!/bin/bash
# Local testing script for RSOLV-action using act
# Requires: brew install act
#
# Usage:
#   ./test-local.sh              # Test default workflow
#   ./test-local.sh 123          # Test with specific issue number
#   ./test-local.sh prod         # Test against production API

echo "🧪 Testing RSOLV-action locally with act..."

# Default to staging API
API_URL="https://api.rsolv-staging.com"
API_KEY="${RSOLV_STAGING_API_KEY:-test-key}"

# Check for production flag
if [[ "$1" == "prod" ]]; then
    echo "⚠️  Testing against PRODUCTION API..."
    API_URL="https://api.rsolv.dev"
    API_KEY="${RSOLV_API_KEY:-$API_KEY}"
    shift  # Remove 'prod' from arguments
fi

# Test with staging API
echo "Testing against: $API_URL"
act -s RSOLV_API_KEY="$API_KEY" \
    -s GITHUB_TOKEN="${GITHUB_TOKEN}" \
    --var RSOLV_API_URL="$API_URL" \
    -W .github/workflows/rsolv-dogfood.yml \
    -j rsolv-automation \
    --container-architecture linux/amd64

# Test specific issue if provided
if [ -n "$1" ]; then
    echo "Testing with specific issue #$1..."
    act workflow_dispatch \
        -s RSOLV_API_KEY="$API_KEY" \
        -s GITHUB_TOKEN="${GITHUB_TOKEN}" \
        --var RSOLV_API_URL="$API_URL" \
        -W .github/workflows/manual-trigger.yml \
        --input issue_number="$1" \
        --container-architecture linux/amd64
fi