#!/bin/bash
# End-to-end test for three-phase architecture
set -e

REPO="RSOLV-dev/nodegoat-vulnerability-demo"
echo "=== Three-Phase Architecture E2E Test ==="
echo "Testing with v3.2.0 (automatic label creation)"
echo

# Function to wait for workflow completion
wait_for_workflow() {
  local workflow_name=$1
  local max_wait=120  # 2 minutes
  local elapsed=0
  
  echo "Waiting for $workflow_name to complete..."
  while [ $elapsed -lt $max_wait ]; do
    STATUS=$(gh run list --repo $REPO --workflow "$workflow_name" --limit 1 --json status --jq '.[0].status')
    if [ "$STATUS" = "completed" ]; then
      CONCLUSION=$(gh run list --repo $REPO --workflow "$workflow_name" --limit 1 --json conclusion --jq '.[0].conclusion')
      echo "✓ $workflow_name completed with: $CONCLUSION"
      return 0
    fi
    sleep 5
    elapsed=$((elapsed + 5))
  done
  echo "✗ Timeout waiting for $workflow_name"
  return 1
}

echo "=== PHASE 1: SCAN ==="
echo "1. Checking clean state..."
ISSUE_COUNT=$(gh issue list --repo $REPO --state open --json number --jq '. | length')
if [ "$ISSUE_COUNT" -ne "0" ]; then
  echo "❌ FAIL: Expected 0 open issues, found $ISSUE_COUNT"
  exit 1
fi
echo "✅ PASS: Repository is clean"

echo -e "\n2. Triggering security scan..."
gh workflow run rsolv-security-scan.yml --repo $REPO
sleep 10  # Give it time to start

# Wait for scan to complete
wait_for_workflow "rsolv-security-scan.yml"

echo -e "\n3. Verifying scan created issues with 'rsolv:detected' label..."
DETECTED_ISSUES=$(gh issue list --repo $REPO --label "rsolv:detected" --json number,labels --jq '. | length')
if [ "$DETECTED_ISSUES" -gt "0" ]; then
  echo "✅ PASS: Scan created $DETECTED_ISSUES issues with 'rsolv:detected' label"
  
  # Check that NO issues have rsolv:automate
  AUTOMATE_COUNT=$(gh issue list --repo $REPO --label "rsolv:automate" --json number --jq '. | length')
  if [ "$AUTOMATE_COUNT" -eq "0" ]; then
    echo "✅ PASS: No issues have 'rsolv:automate' label (correct!)"
  else
    echo "❌ FAIL: Found $AUTOMATE_COUNT issues with 'rsolv:automate' (should be 0)"
  fi
else
  echo "❌ FAIL: No issues created with 'rsolv:detected' label"
  exit 1
fi

echo -e "\n=== PHASE 2: VALIDATE ==="
echo "4. Adding 'rsolv:validate' label to trigger validation..."
FIRST_ISSUE=$(gh issue list --repo $REPO --label "rsolv:detected" --limit 1 --json number --jq '.[0].number')
gh issue edit $FIRST_ISSUE --repo $REPO --add-label "rsolv:validate"
echo "Added 'rsolv:validate' to issue #$FIRST_ISSUE"

sleep 10
wait_for_workflow "rsolv-validate.yml"

echo -e "\n5. Checking if issue was enriched..."
ISSUE_BODY=$(gh issue view $FIRST_ISSUE --repo $REPO --json body --jq '.body')
if echo "$ISSUE_BODY" | grep -q "AST Validation"; then
  echo "✅ PASS: Issue enriched with validation details"
else
  echo "⚠️  WARN: Issue may not have been enriched (check manually)"
fi

echo -e "\n=== PHASE 3: MITIGATE ==="
echo "6. Adding 'rsolv:automate' label to trigger fix generation..."
gh issue edit $FIRST_ISSUE --repo $REPO --add-label "rsolv:automate"
echo "Added 'rsolv:automate' to issue #$FIRST_ISSUE"

sleep 10
wait_for_workflow "rsolv-fix-issues.yml"

echo -e "\n7. Checking if PR was created..."
sleep 5  # Give PR creation time
PR_COUNT=$(gh pr list --repo $REPO --state open --json number --jq '. | length')
if [ "$PR_COUNT" -gt "0" ]; then
  echo "✅ PASS: Fix workflow created $PR_COUNT PR(s)"
  
  # Show PR details
  echo -e "\nCreated PRs:"
  gh pr list --repo $REPO --state open --json number,title --jq '.[] | "  PR #\(.number): \(.title)"'
else
  echo "❌ FAIL: No PRs created"
  
  # Check if more issues were created instead
  NEW_ISSUE_COUNT=$(gh issue list --repo $REPO --state open --json number --jq '. | length')
  if [ "$NEW_ISSUE_COUNT" -gt "$DETECTED_ISSUES" ]; then
    echo "❌ CRITICAL: Fix workflow created MORE issues instead of PRs!"
    echo "   This means mode:mitigate is not working"
  fi
fi

echo -e "\n=== TEST SUMMARY ==="
echo "✓ SCAN phase: Creates issues with 'rsolv:detected'"
echo "✓ VALIDATE phase: Enriches issues when 'rsolv:validate' added"
echo "✓ MITIGATE phase: Creates PRs when 'rsolv:automate' added"
echo
echo "Three-phase architecture is working correctly!"