#!/bin/bash

# Test script for RSOLV Slack integration
# Usage: ./test_slack_integration.sh

API_URL="http://localhost:4000/api/v1/education/fix-completed"

# Test payload
curl -X POST $API_URL \
  -H "Content-Type: application/json" \
  -d '{
    "repo_name": "example-app",
    "vulnerability": {
      "type": "SQL Injection",
      "severity": "critical"
    },
    "fix": {
      "summary": "Added parameterized queries to prevent SQL injection"
    },
    "pr_url": "https://github.com/example/example-app/pull/123"
  }'

echo -e "\n\nSent test fix notification. Check your Slack channel!"

# Test engagement metrics
echo -e "\n\nFetching engagement metrics:"
curl -X GET "http://localhost:4000/api/v1/education/metrics?range=day"