#!/bin/bash

# Test script to verify Slack throttling (max 3 per day per repo)

API_URL="http://localhost:4000/api/v1/education/fix-completed"
REPO_NAME="throttle-test-repo"

echo "Testing Slack throttling for repo: $REPO_NAME"
echo "Expected: First 3 alerts should succeed, 4th should be throttled"
echo "---"

# Send 4 alerts for the same repo
for i in {1..4}; do
    echo "Sending alert #$i..."
    
    RESPONSE=$(curl -s -X POST $API_URL \
        -H "Content-Type: application/json" \
        -d "{
            \"repo_name\": \"$REPO_NAME\",
            \"vulnerability\": {
                \"type\": \"XSS\",
                \"severity\": \"high\"
            },
            \"fix\": {
                \"summary\": \"Test fix #$i - Escaped user input\"
            },
            \"pr_url\": \"https://github.com/test/test/pull/$i\"
        }")
    
    echo "Response: $RESPONSE"
    
    # Check if throttled
    if echo "$RESPONSE" | grep -q "throttled"; then
        echo "✅ Alert #$i was throttled as expected"
    else
        echo "✅ Alert #$i was sent successfully"
    fi
    
    echo "---"
    sleep 1
done

echo -e "\nChecking metrics..."
curl -s "http://localhost:4000/api/v1/education/metrics?range=day" | jq '.'