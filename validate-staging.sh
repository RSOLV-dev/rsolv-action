#!/bin/bash
# Quick validation of staging environment readiness

echo "🔍 Validating Staging Environment..."
echo "===================================="

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Staging endpoints
API_URL="https://api.rsolv-staging.com"
LANDING_URL="https://rsolv-staging.com"

# Check functions
check() {
    if eval "$2"; then
        echo -e "${GREEN}✅ $1${NC}"
        return 0
    else
        echo -e "${RED}❌ $1${NC}"
        return 1
    fi
}

# 1. API Health
check "API Health" "curl -s $API_URL/health | jq -e '.status == \"healthy\"' > /dev/null"

# 2. Database
check "Database Connectivity" "curl -s $API_URL/health | jq -e '.services.database == \"healthy\"' > /dev/null"

# 3. AI Providers
check "AI Providers" "curl -s $API_URL/health | jq -e '.services.ai_providers.anthropic == \"healthy\"' > /dev/null"

# 4. Clustering
check "BEAM Clustering" "curl -s $API_URL/health | jq -e '.clustering.enabled == true and .clustering.node_count >= 1' > /dev/null"

# 5. Pattern API
check "Pattern API" "curl -s $API_URL/api/v1/patterns/javascript | jq -e '.patterns | length > 0' > /dev/null"

# 6. Django Patterns
check "Django Patterns" "curl -s '$API_URL/api/v1/patterns/python?framework=django' | jq -e '.patterns | length > 0' > /dev/null"

# 7. Landing Page
check "Landing Page" "curl -s -o /dev/null -w '%{http_code}' $LANDING_URL | grep -q '200'"

# 8. Landing Health
check "Landing Health" "curl -s $LANDING_URL/health | jq -e '.status == \"ok\"' > /dev/null 2>&1 || curl -s -o /dev/null -w '%{http_code}' $LANDING_URL/health | grep -q '200'"

echo ""
echo "===================================="
echo "Staging validation complete!"