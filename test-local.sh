#!/bin/bash

# This script makes it easier to test the RSOLV Action locally with Docker

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}RSOLV Action Local Testing${NC}"
echo "--------------------------------"

# Check for Anthropic API key
if [ -z "$1" ]; then
  echo -e "${RED}Error: Missing Anthropic API key${NC}"
  echo "Usage: ./test-local.sh YOUR_ANTHROPIC_API_KEY"
  exit 1
fi

ANTHROPIC_API_KEY=$1

echo -e "${GREEN}Step 1: Building Docker image...${NC}"
docker build --load -t rsolv-action .

if [ $? -ne 0 ]; then
  echo -e "${RED}Error: Docker build failed${NC}"
  exit 1
fi

echo -e "${GREEN}Step 2: Running Docker container with sample event...${NC}"
docker run -e INPUT_API_KEY=rsolv_12345678901234567890123456789012 \
           -e INPUT_ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
           -e INPUT_ISSUE_TAG=AUTOFIX \
           -e INPUT_DEBUG=true \
           -e INPUT_SKIP_SECURITY_CHECK=true \
           -e GITHUB_EVENT_PATH=/tmp/event.json \
           -e GITHUB_TOKEN=github_pat_test_token \
           -v $(pwd)/sample-event.json:/tmp/event.json \
           rsolv-action

if [ $? -ne 0 ]; then
  echo -e "${RED}Error: Docker run failed${NC}"
  exit 1
fi

echo -e "${GREEN}Test completed successfully!${NC}"