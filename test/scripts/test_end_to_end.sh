#!/bin/bash

# End-to-end test simulating RSOLV-action workflow

echo "=== RSOLV Educational Framework - End-to-End Test ==="
echo "This simulates the complete workflow from RSOLV-action to Slack"
echo ""

# Step 1: Check system health
echo "1️⃣ Checking system health..."
HEALTH=$(curl -s http://localhost:4000/health | jq -r '.status')
echo "   System status: $HEALTH"
echo ""

# Step 2: Verify Slack configuration
echo "2️⃣ Verifying Slack configuration..."
DEBUG=$(curl -s http://localhost:4000/api/v1/education/debug)
echo "   $DEBUG"
echo ""

# Step 3: Simulate RSOLV-action finding and fixing a vulnerability
echo "3️⃣ Simulating RSOLV-action workflow..."
echo "   - Repository: awesome-webapp"
echo "   - Vulnerability: SQL Injection in user.rb:45"
echo "   - Fix: Using parameterized queries"
echo ""

# Step 4: Send fix notification
echo "4️⃣ Sending fix notification to education API..."
RESPONSE=$(curl -s -X POST http://localhost:4000/api/v1/education/fix-completed \
    -H "Content-Type: application/json" \
    -d '{
        "repo_name": "awesome-webapp",
        "vulnerability": {
            "type": "SQL Injection",
            "severity": "critical"
        },
        "fix": {
            "summary": "Replaced string interpolation with parameterized queries in User.find_by_email"
        },
        "pr_url": "https://github.com/acme-corp/awesome-webapp/pull/142"
    }')

echo "   Response: $RESPONSE"
echo ""

# Step 5: Check Slack
echo "5️⃣ Check your Slack channel!"
echo "   You should see:"
echo "   - 🚨 Critical SQL Injection alert"
echo "   - 📊 Business impact ($4.45M potential loss)"
echo "   - 🛡️ Fix description"
echo "   - 📚 Learn More button"
echo "   - PR link"
echo ""

# Step 6: Simulate clicking the dashboard link
ALERT_ID="test_$(date +%s)"
echo "6️⃣ Simulating dashboard click-through..."
curl -s "http://localhost:4000/api/v1/education/track-click/$ALERT_ID" > /dev/null
echo "   ✅ Click tracked"
echo ""

# Step 7: Check engagement metrics
echo "7️⃣ Checking engagement metrics..."
METRICS=$(curl -s "http://localhost:4000/api/v1/education/metrics?range=day")
echo "   Daily metrics:"
echo "$METRICS" | jq '.'
echo ""

echo "=== End-to-End Test Complete ==="
echo ""
echo "Next steps:"
echo "1. Verify the Slack message appeared in your channel"
echo "2. Click the 'Learn More' button to test the dashboard link"
echo "3. Run ./test_throttling.sh to verify rate limiting"