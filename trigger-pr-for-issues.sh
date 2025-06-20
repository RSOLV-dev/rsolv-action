#!/bin/bash
# Script to trigger RSOLV-action on each security issue

echo "🔄 Triggering PR generation for security issues..."

# Set the repository
REPO="RSOLV-dev/nodegoat-vulnerability-demo"

# Get all issue numbers with rsolv:security label
ISSUES=$(gh issue list --repo "$REPO" --label "rsolv:security" --state open --json number --jq '.[].number')

echo "Found issues: $ISSUES"

for ISSUE_NUM in $ISSUES; do
  echo ""
  echo "📋 Processing issue #$ISSUE_NUM..."
  
  # Add the rsolv:automate label to trigger RSOLV action
  gh issue edit "$ISSUE_NUM" --repo "$REPO" --add-label "rsolv:automate"
  
  echo "✅ Added rsolv:automate label to issue #$ISSUE_NUM"
  
  # Wait a bit between issues
  sleep 2
done

echo ""
echo "🎉 All issues have been labeled for PR generation!"
echo "Check the Actions tab on GitHub to monitor progress."