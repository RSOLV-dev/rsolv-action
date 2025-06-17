#!/bin/bash
# Test RSOLV-action locally using github/local-action
# This allows testing the actual action.yml without workflows

echo "🧪 Testing RSOLV-action locally..."

# Install local-action if not present
if ! command -v local-action &> /dev/null; then
    echo "Installing github/local-action..."
    npm install -g @github/local-action
fi

# Create test env file
cat > .env.test <<EOF
RSOLV_API_KEY=${RSOLV_STAGING_API_KEY:-test-staging-key}
GITHUB_TOKEN=${GITHUB_TOKEN}
GITHUB_REPOSITORY=${GITHUB_REPOSITORY:-RSOLV-dev/test-repo}
GITHUB_ACTOR=${USER}
GITHUB_REF=refs/heads/main
GITHUB_SHA=$(git rev-parse HEAD)
GITHUB_WORKSPACE=$(pwd)
EOF

# Test the action locally
echo "Running action with staging configuration..."
local-action . \
  --env-file .env.test \
  --input api_key="${RSOLV_STAGING_API_KEY:-test-key}" \
  --input api_url="https://api.rsolv-staging.com" \
  --input issue_label="rsolv:staging-test" \
  --input config_path=".github/rsolv-staging.yml"

# Clean up
rm -f .env.test