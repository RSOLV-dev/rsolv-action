#!/bin/bash

# End-to-End Production Test Script
# This script tests the complete RSOLV workflow from issue creation to PR generation

set -e

echo "🚀 Starting RSOLV Production E2E Test"
echo "=================================="

# Configuration
REPO="RSOLV-dev/test-security-issues"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
RSOLV_API_KEY="${RSOLV_API_KEY:-}"

if [ -z "$GITHUB_TOKEN" ]; then
    echo "❌ Error: GITHUB_TOKEN is not set"
    exit 1
fi

# Create a test issue with security vulnerabilities
echo "📝 Creating test issue with security vulnerabilities..."
ISSUE_RESPONSE=$(gh api \
    --method POST \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "/repos/$REPO/issues" \
    -f title="[E2E Test] Security vulnerabilities in authentication" \
    -f body="## Problem Description

We have several security issues in our authentication code that need to be fixed.

### Current vulnerable code:

\`\`\`javascript
// auth.js
const mysql = require('mysql');
const crypto = require('crypto');

function authenticateUser(username, password) {
    // SQL Injection vulnerability
    const query = \"SELECT * FROM users WHERE username = '\" + username + \"' AND password = '\" + password + \"'\";
    db.query(query, (err, results) => {
        if (results.length > 0) {
            // Weak crypto
            const token = crypto.createHash('md5').update(username + Date.now()).digest('hex');
            
            // XSS vulnerability
            document.getElementById('welcome').innerHTML = 'Welcome ' + username;
            
            return token;
        }
    });
}

// Command injection
const exec = require('child_process').exec;
function logUserActivity(userId, action) {
    exec('echo \"User ' + userId + ' performed ' + action + '\" >> /var/log/app.log');
}
\`\`\`

Please fix these security vulnerabilities following OWASP best practices.")

ISSUE_NUMBER=$(echo "$ISSUE_RESPONSE" | jq -r '.number')
ISSUE_URL=$(echo "$ISSUE_RESPONSE" | jq -r '.html_url')

echo "✅ Created issue #$ISSUE_NUMBER: $ISSUE_URL"

# Add labels to the issue
echo "🏷️  Adding labels to issue..."
gh issue edit "$ISSUE_NUMBER" --repo "$REPO" --add-label "security" --add-label "rsolv:automate"

# Wait a moment for GitHub to process the issue
sleep 2

# Trigger RSOLV workflow
echo "🔧 Triggering RSOLV workflow..."
if command -v gh &> /dev/null; then
    gh workflow run manual-trigger.yml \
        -R RSOLV-dev/rsolv-action \
        -f issue_number="$ISSUE_NUMBER" \
        -f repository="$REPO"
    
    echo "✅ Workflow triggered successfully"
    echo ""
    echo "📊 Monitoring workflow status..."
    echo "View at: https://github.com/RSOLV-dev/rsolv-action/actions"
    
    # Wait for workflow to start
    sleep 10
    
    # Check workflow runs
    echo ""
    echo "Recent workflow runs:"
    gh run list -R RSOLV-dev/rsolv-action --workflow=manual-trigger.yml --limit 3
    
else
    echo "⚠️  GitHub CLI not available. Please manually trigger the workflow:"
    echo "   1. Go to https://github.com/RSOLV-dev/rsolv-action/actions/workflows/manual-trigger.yml"
    echo "   2. Click 'Run workflow'"
    echo "   3. Enter issue number: $ISSUE_NUMBER"
    echo "   4. Enter repository: $REPO"
fi

echo ""
echo "🔍 Testing API endpoints..."

# Test pattern API
echo "Testing pattern API..."
PATTERN_COUNT=$(curl -s "https://api.rsolv.dev/api/v1/patterns?language=javascript" \
    -H "Authorization: Bearer ${RSOLV_API_KEY:-test}" | \
    jq -r '.metadata.count // 0')
echo "✅ Pattern API returned $PATTERN_COUNT JavaScript patterns"

# Test health endpoint
echo "Testing health endpoint..."
HEALTH_STATUS=$(curl -s "https://api.rsolv.dev/health" | jq -r '.status // "unknown"')
NODE_COUNT=$(curl -s "https://api.rsolv.dev/health" | jq -r '.clustering.node_count // 0')
echo "✅ API health: $HEALTH_STATUS (clustering: $NODE_COUNT nodes)"

echo ""
echo "=================================="
echo "🎯 E2E Test Summary:"
echo "- Issue created: #$ISSUE_NUMBER"
echo "- Issue URL: $ISSUE_URL"
echo "- Patterns available: $PATTERN_COUNT"
echo "- API status: $HEALTH_STATUS"
echo "- Workflow: Triggered"
echo ""
echo "Next steps:"
echo "1. Monitor workflow at: https://github.com/RSOLV-dev/rsolv-action/actions"
echo "2. Check for PR creation at: https://github.com/$REPO/pulls"
echo "3. Verify fix attempt tracked at: https://api.rsolv.dev/api/v1/fix-attempts"
echo "=================================="