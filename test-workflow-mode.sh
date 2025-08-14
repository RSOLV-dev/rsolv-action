#!/bin/bash
# Test to verify current workflow mode issue (RED phase of TDD)

echo "=== Testing Current Workflow Mode Issue ==="
echo "This should FAIL with current setup - workflows run wrong mode"
echo

REPO="RSOLV-dev/nodegoat-vulnerability-demo"

# Step 1: Check current workflow files
echo "1. Checking current workflow files..."
gh api repos/$REPO/contents/.github/workflows --jq '.[] | select(.name | contains("rsolv")) | .name'

# Step 2: Verify Fix workflow lacks mode parameter
echo -e "\n2. Checking Fix workflow for mode parameter..."
FIX_WORKFLOW=$(gh api repos/$REPO/contents/.github/workflows/rsolv-fix-issues.yml --jq '.content' | base64 -d)
if echo "$FIX_WORKFLOW" | grep -q "mode:"; then
    echo "✅ PASS: Fix workflow has mode parameter"
else
    echo "❌ FAIL: Fix workflow missing mode parameter (will default to 'full')"
fi

# Step 3: Check if it uses correct action version
echo -e "\n3. Checking action version..."
if echo "$FIX_WORKFLOW" | grep -q "RSOLV-dev/rsolv-action@v3.1.1"; then
    echo "✅ PASS: Using v3.1.1"
elif echo "$FIX_WORKFLOW" | grep -q "RSOLV-dev/rsolv-action@main"; then
    echo "❌ FAIL: Still using @main instead of v3.1.1"
else
    ACTION_VERSION=$(echo "$FIX_WORKFLOW" | grep "RSOLV-dev/rsolv-action@" | head -1)
    echo "❓ Using: $ACTION_VERSION"
fi

# Step 4: Check for validate workflow
echo -e "\n4. Checking for Validate workflow..."
if gh api repos/$REPO/contents/.github/workflows/rsolv-validate.yml &>/dev/null; then
    echo "✅ PASS: Validate workflow exists"
else
    echo "❌ FAIL: No validate workflow (missing middle phase)"
fi

# Step 5: Check trigger conditions
echo -e "\n5. Checking Fix workflow triggers..."
if echo "$FIX_WORKFLOW" | grep -q "types: \[opened, labeled\]"; then
    echo "❌ FAIL: Triggers on 'opened' (should only trigger on 'labeled')"
elif echo "$FIX_WORKFLOW" | grep -q "types: \[labeled\]"; then
    echo "✅ PASS: Only triggers on 'labeled'"
else
    echo "❓ Unclear trigger configuration"
fi

# Summary
echo -e "\n=== Test Summary ==="
echo "Expected result: Multiple FAILs showing the current issues"
echo "After fix: All should PASS"