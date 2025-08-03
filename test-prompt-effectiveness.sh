#!/bin/bash
# Test script to validate Claude's git-based editing behavior
# RED-GREEN-REFACTOR approach to prompt engineering

set -e

echo "=== Prompt Effectiveness Test ==="
echo "Testing if Claude both edits files AND provides JSON solution"
echo ""

# Configuration
REPO="RSOLV-dev/rsolv-demo-vulnerable-app"
ISSUE_NUMBER=3
TEST_RUN_ID=""

# Function to check if files were modified
check_files_modified() {
    local run_id=$1
    echo "Checking if files were modified in run $run_id..."
    
    # Check logs for "No files were modified" error
    if gh run view $run_id --repo $REPO --log 2>/dev/null | grep -q "No files were modified"; then
        echo "❌ FAILED: No files were modified by Claude"
        return 1
    else
        echo "✅ PASSED: Files were modified"
        return 0
    fi
}

# Function to check if JSON solution was provided
check_json_solution() {
    local run_id=$1
    echo "Checking if JSON solution was provided in run $run_id..."
    
    # Check logs for solution found messages
    if gh run view $run_id --repo $REPO --log 2>/dev/null | grep -q "Solution found with.*file.*to change"; then
        echo "✅ PASSED: JSON solution was provided"
        return 0
    else
        echo "❌ FAILED: No JSON solution found"
        return 1
    fi
}

# Function to check if PR was created
check_pr_created() {
    echo "Checking if PR was created..."
    
    # Check for open PRs
    if gh pr list --repo $REPO --state open | grep -q "Fix.*XSS"; then
        echo "✅ PASSED: PR was created"
        return 0
    else
        echo "❌ FAILED: No PR was created"
        return 1
    fi
}

# Main test execution
run_test() {
    echo "1. Triggering autofix workflow..."
    gh issue comment $ISSUE_NUMBER --repo $REPO --body "@rsolv-action autofix - Prompt test $(date +%s)"
    
    echo "2. Waiting for workflow to start..."
    sleep 10
    
    # Get the latest run ID
    TEST_RUN_ID=$(gh run list --repo $REPO --limit 1 --json databaseId --jq '.[0].databaseId')
    echo "   Workflow run ID: $TEST_RUN_ID"
    
    echo "3. Waiting for workflow to complete (max 5 minutes)..."
    local max_wait=300
    local waited=0
    while [ $waited -lt $max_wait ]; do
        if gh run view $TEST_RUN_ID --repo $REPO --json status --jq '.status' 2>/dev/null | grep -q "completed"; then
            echo "   Workflow completed!"
            break
        fi
        sleep 10
        waited=$((waited + 10))
        echo "   Still running... ($waited seconds)"
    done
    
    echo ""
    echo "4. Running test assertions..."
    
    local test_passed=true
    
    if ! check_files_modified $TEST_RUN_ID; then
        test_passed=false
    fi
    
    if ! check_json_solution $TEST_RUN_ID; then
        test_passed=false
    fi
    
    if ! check_pr_created; then
        test_passed=false
    fi
    
    echo ""
    if [ "$test_passed" = true ]; then
        echo "🎉 ALL TESTS PASSED!"
        echo "Claude successfully:"
        echo "  - Modified files using Edit/MultiEdit tools"
        echo "  - Provided JSON solution summary"
        echo "  - Created a PR with the fix"
        return 0
    else
        echo "🔴 TESTS FAILED"
        echo "Claude did not complete all required steps"
        echo "View full logs: gh run view $TEST_RUN_ID --repo $REPO --log"
        return 1
    fi
}

# Execute the test
run_test