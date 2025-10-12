#!/bin/bash

# Test script to verify emergency alert throttling
# This simulates what Alertmanager would send to our webhook

WEBHOOK_URL="${WEBHOOK_URL:-http://localhost:8080/webhook}"

echo "Testing Emergency Alert Throttling"
echo "===================================="
echo "Webhook URL: $WEBHOOK_URL"
echo ""

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test 1: Send a firing alert (should be handled by Alertmanager, not webhook)
echo -e "${YELLOW}Test 1: Firing alert (webhook should ignore)${NC}"
curl -s -X POST "$WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "version": "4",
    "groupKey": "{}:{alertname=\"RSOLVMainSiteDown\"}",
    "status": "firing",
    "alerts": [
      {
        "status": "firing",
        "labels": {
          "alertname": "RSOLVMainSiteDown",
          "instance": "https://rsolv.dev",
          "severity": "critical"
        },
        "annotations": {
          "summary": "RSOLV Main Site is DOWN",
          "description": "The main RSOLV website has been unreachable for more than 2 minutes."
        },
        "startsAt": "2025-10-12T10:00:00Z",
        "endsAt": "0001-01-01T00:00:00Z",
        "generatorURL": "http://prometheus:9090/graph"
      }
    ]
  }'
echo -e "\n${GREEN}✓ Firing alert sent${NC}\n"
sleep 2

# Test 2: Send first recovery alert (should send email)
echo -e "${YELLOW}Test 2: First recovery alert (should send email)${NC}"
curl -s -X POST "$WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "version": "4",
    "groupKey": "{}:{alertname=\"RSOLVMainSiteDown\"}",
    "status": "resolved",
    "alerts": [
      {
        "status": "resolved",
        "labels": {
          "alertname": "RSOLVMainSiteDown",
          "instance": "https://rsolv.dev",
          "severity": "critical"
        },
        "annotations": {
          "summary": "RSOLV Main Site is DOWN",
          "description": "The main RSOLV website has been unreachable for more than 2 minutes."
        },
        "startsAt": "2025-10-12T10:00:00Z",
        "endsAt": "2025-10-12T10:05:00Z",
        "generatorURL": "http://prometheus:9090/graph"
      }
    ]
  }'
echo -e "\n${GREEN}✓ First recovery sent (should trigger email)${NC}\n"
sleep 2

# Test 3: Send duplicate recovery alert within 5 minutes (should be throttled)
echo -e "${YELLOW}Test 3: Duplicate recovery within throttle window (should be throttled)${NC}"
curl -s -X POST "$WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "version": "4",
    "groupKey": "{}:{alertname=\"RSOLVMainSiteDown\"}",
    "status": "resolved",
    "alerts": [
      {
        "status": "resolved",
        "labels": {
          "alertname": "RSOLVMainSiteDown",
          "instance": "https://rsolv.dev",
          "severity": "critical"
        },
        "annotations": {
          "summary": "RSOLV Main Site is DOWN",
          "description": "The main RSOLV website has been unreachable for more than 2 minutes."
        },
        "startsAt": "2025-10-12T10:00:00Z",
        "endsAt": "2025-10-12T10:05:00Z",
        "generatorURL": "http://prometheus:9090/graph"
      }
    ]
  }'
echo -e "\n${GREEN}✓ Duplicate recovery sent (should be throttled)${NC}\n"
sleep 2

# Test 4: Send recovery for different instance (should send email)
echo -e "${YELLOW}Test 4: Recovery for different instance (should send email)${NC}"
curl -s -X POST "$WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "version": "4",
    "groupKey": "{}:{alertname=\"RSOLVMainSiteDown\"}",
    "status": "resolved",
    "alerts": [
      {
        "status": "resolved",
        "labels": {
          "alertname": "RSOLVMainSiteDown",
          "instance": "https://rsolv.dev/blog",
          "severity": "critical"
        },
        "annotations": {
          "summary": "RSOLV Blog is DOWN",
          "description": "The RSOLV blog has been unreachable for more than 5 minutes."
        },
        "startsAt": "2025-10-12T10:00:00Z",
        "endsAt": "2025-10-12T10:05:00Z",
        "generatorURL": "http://prometheus:9090/graph"
      }
    ]
  }'
echo -e "\n${GREEN}✓ Different instance recovery sent (should trigger email)${NC}\n"

echo ""
echo -e "${GREEN}===============================================${NC}"
echo -e "${GREEN}Test Complete!${NC}"
echo -e "${GREEN}===============================================${NC}"
echo ""
echo "Expected behavior:"
echo "1. Firing alert - No email (handled by Alertmanager directly)"
echo "2. First recovery - Email sent via webhook"
echo "3. Duplicate recovery - Throttled (no email)"
echo "4. Different instance - Email sent (different alert key)"
echo ""
echo "Check the webhook receiver logs to verify:"
echo "  kubectl logs -n monitoring deployment/webhook-receiver"
