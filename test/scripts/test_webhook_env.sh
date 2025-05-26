#!/bin/bash

echo "Testing Slack webhook environment..."

# Check if webhook is set
if [ -z "$SLACK_WEBHOOK_URL" ]; then
    echo "❌ SLACK_WEBHOOK_URL is not set!"
    echo "Please run: source ../.envrc"
else
    echo "✅ SLACK_WEBHOOK_URL is set"
    echo "   Length: ${#SLACK_WEBHOOK_URL} characters"
    echo "   Starts with: ${SLACK_WEBHOOK_URL:0:30}..."
    
    # Test direct curl
    echo -e "\nTesting direct curl to Slack..."
    curl -X POST "$SLACK_WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d '{"text": "🔐 RSOLV Test Message - Direct curl test"}' \
        -w "\nHTTP Status: %{http_code}\n"
fi