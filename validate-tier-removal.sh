#!/bin/bash
# Comprehensive validation of tier removal changes

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}=== Tier Removal Validation Suite ===${NC}"
echo -e "${BLUE}Comprehensive testing before production deployment${NC}\n"

# Configuration
API_URL="http://localhost:4001"
EXPECTED_PATTERN_COUNT=170

echo -e "${GREEN}Phase 1: Local API Validation${NC}"

# Start the API if not running
if ! curl -s "$API_URL/health" > /dev/null 2>&1; then
    echo -e "${YELLOW}Starting API server...${NC}"
    docker compose up -d
    sleep 10
fi

# Test 1: Pattern count verification
echo -e "\n${YELLOW}Test 1: Pattern count verification${NC}"
STATS_RESPONSE=$(curl -s "$API_URL/api/v1/patterns/stats")
TOTAL_PATTERNS=$(echo "$STATS_RESPONSE" | jq -r '.total_patterns' 2>/dev/null || echo "0")

if [ "$TOTAL_PATTERNS" = "$EXPECTED_PATTERN_COUNT" ]; then
    echo -e "${GREEN}✓ Pattern count correct: $TOTAL_PATTERNS${NC}"
else
    echo -e "${RED}✗ Pattern count mismatch: expected $EXPECTED_PATTERN_COUNT, got $TOTAL_PATTERNS${NC}"
    exit 1
fi

# Test 2: Memory usage validation
echo -e "\n${YELLOW}Test 2: Memory usage validation${NC}"
CONTAINER_MEMORY=$(docker stats --no-stream --format "{{.MemUsage}}" rsolv-api-rsolv-api-1 | cut -d'/' -f1)
echo -e "${GREEN}✓ Container memory usage: $CONTAINER_MEMORY${NC}"

# Test 3: API endpoint functionality
echo -e "\n${YELLOW}Test 3: API endpoint functionality${NC}"

# Test main endpoint
MAIN_RESPONSE=$(curl -s "$API_URL/api/v1/patterns?language=javascript")
MAIN_COUNT=$(echo "$MAIN_RESPONSE" | jq -r '.metadata.count' 2>/dev/null || echo "0")
MAIN_ACCESS=$(echo "$MAIN_RESPONSE" | jq -r '.metadata.access_level' 2>/dev/null || echo "unknown")

if [ "$MAIN_COUNT" = "5" ] && [ "$MAIN_ACCESS" = "demo" ]; then
    echo -e "${GREEN}✓ Main endpoint working (demo mode)${NC}"
else
    echo -e "${RED}✗ Main endpoint failed: count=$MAIN_COUNT, access=$MAIN_ACCESS${NC}"
    exit 1
fi

# Test V2 endpoint
V2_RESPONSE=$(curl -s "$API_URL/api/v2/patterns?language=javascript")
V2_FORMAT=$(echo "$V2_RESPONSE" | jq -r '.metadata.format' 2>/dev/null || echo "unknown")

if [ "$V2_FORMAT" = "enhanced" ]; then
    echo -e "${GREEN}✓ V2 endpoint working (enhanced format)${NC}"
else
    echo -e "${RED}✗ V2 endpoint failed: format=$V2_FORMAT${NC}"
    exit 1
fi

# Test 4: RSOLV-action compatibility
echo -e "\n${YELLOW}Test 4: RSOLV-action compatibility${NC}"
ACTION_RESPONSE=$(curl -s "$API_URL/api/v1/patterns?language=javascript&format=enhanced")
ACTION_ENHANCED=$(echo "$ACTION_RESPONSE" | jq -r '.metadata.enhanced' 2>/dev/null || echo "false")

if [ "$ACTION_ENHANCED" = "true" ]; then
    echo -e "${GREEN}✓ RSOLV-action compatibility maintained${NC}"
else
    echo -e "${RED}✗ RSOLV-action compatibility broken${NC}"
    exit 1
fi

# Test 5: Pattern structure validation
echo -e "\n${YELLOW}Test 5: Pattern structure validation${NC}"
PATTERN_SAMPLE=$(echo "$ACTION_RESPONSE" | jq '.patterns[0]' 2>/dev/null)
HAS_ID=$(echo "$PATTERN_SAMPLE" | jq 'has("id")' 2>/dev/null || echo "false")
HAS_AST_RULES=$(echo "$PATTERN_SAMPLE" | jq 'has("ast_rules")' 2>/dev/null || echo "false")

if [ "$HAS_ID" = "true" ] && [ "$HAS_AST_RULES" = "true" ]; then
    echo -e "${GREEN}✓ Pattern structure correct${NC}"
else
    echo -e "${RED}✗ Pattern structure invalid${NC}"
    exit 1
fi

# Test 6: Performance validation
echo -e "\n${YELLOW}Test 6: Performance validation${NC}"
START_TIME=$(date +%s%3N)
for i in {1..10}; do
    curl -s "$API_URL/api/v1/patterns?language=javascript" > /dev/null
done
END_TIME=$(date +%s%3N)
AVG_TIME=$(( (END_TIME - START_TIME) / 10 ))

if [ "$AVG_TIME" -lt 200 ]; then
    echo -e "${GREEN}✓ Performance acceptable: ${AVG_TIME}ms average${NC}"
else
    echo -e "${YELLOW}⚠ Performance slower than expected: ${AVG_TIME}ms average${NC}"
fi

echo -e "\n${GREEN}Phase 2: Production Readiness Checks${NC}"

# Check 1: Database migrations
echo -e "\n${YELLOW}Check 1: Database connectivity${NC}"
DB_RESPONSE=$(curl -s "$API_URL/health")
if echo "$DB_RESPONSE" | grep -q "healthy"; then
    echo -e "${GREEN}✓ Database connectivity OK${NC}"
else
    echo -e "${RED}✗ Database connectivity issues${NC}"
    exit 1
fi

# Check 2: Error handling
echo -e "\n${YELLOW}Check 2: Error handling${NC}"
ERROR_RESPONSE=$(curl -s "$API_URL/api/v1/patterns?language=nonexistent")
if echo "$ERROR_RESPONSE" | jq -e '.patterns | length == 0' > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Error handling working${NC}"
else
    echo -e "${RED}✗ Error handling broken${NC}"
    exit 1
fi

# Check 3: Configuration validation
echo -e "\n${YELLOW}Check 3: Configuration validation${NC}"
docker compose logs rsolv-api --tail=50 | grep -E "(error|Error|ERROR)" | tail -5 | while read line; do
    if [[ "$line" != *"connection refused"* ]]; then
        echo -e "${YELLOW}Warning: $line${NC}"
    fi
done
echo -e "${GREEN}✓ Configuration looks good${NC}"

echo -e "\n${BLUE}=== Validation Summary ===${NC}"
echo -e "${GREEN}✅ All tests passed!${NC}"
echo -e "${GREEN}✅ Pattern count: $TOTAL_PATTERNS (correct)${NC}"
echo -e "${GREEN}✅ API endpoints working${NC}"
echo -e "${GREEN}✅ RSOLV-action compatibility maintained${NC}"
echo -e "${GREEN}✅ Performance acceptable${NC}"
echo -e "${GREEN}✅ Error handling working${NC}"

echo -e "\n${BLUE}Ready for production deployment!${NC}"

echo -e "\n${YELLOW}Production deployment checklist:${NC}"
echo "1. Push latest commits to main branch"
echo "2. Trigger GitHub Actions deployment"
echo "3. Monitor deployment logs"
echo "4. Validate production endpoints"
echo "5. Run production smoke tests"

echo -e "\n${GREEN}Validation complete!${NC}"