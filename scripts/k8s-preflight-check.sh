#!/usr/bin/env bash
# scripts/k8s-preflight-check.sh
#
# Pre-flight check for Kubernetes secrets before deployment
# Usage: ./scripts/k8s-preflight-check.sh <namespace>
#
# Exit codes:
#   0 - All checks passed
#   1 - Required secrets missing or invalid
#   2 - Invalid usage

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

NAMESPACE="${1:-}"
if [ -z "$NAMESPACE" ]; then
  echo "Usage: $0 <namespace>"
  echo "Example: $0 rsolv-production"
  exit 2
fi

echo "========================================"
echo "K8s Secrets Pre-Flight Check"
echo "Namespace: $NAMESPACE"
echo "========================================"
echo ""

# Check if namespace exists
if ! kubectl get namespace "$NAMESPACE" &>/dev/null; then
  echo -e "${RED}✗ FATAL: Namespace '$NAMESPACE' does not exist${NC}"
  exit 1
fi

# Check if secrets object exists
if ! kubectl get secret rsolv-secrets -n "$NAMESPACE" &>/dev/null; then
  echo -e "${RED}✗ FATAL: Secret 'rsolv-secrets' not found in namespace '$NAMESPACE'${NC}"
  exit 1
fi

# Function to check secret exists and is non-empty
check_required_secret() {
  local key=$1
  local validation_pattern=${2:-}

  # Get secret value
  local value
  value=$(kubectl get secret rsolv-secrets -n "$NAMESPACE" -o jsonpath="{.data.$key}" 2>/dev/null | base64 -d 2>/dev/null || echo "")

  if [ -z "$value" ]; then
    echo -e "${RED}✗ CRITICAL: $key is missing or empty${NC}"
    return 1
  fi

  # Validate pattern if provided
  if [ -n "$validation_pattern" ]; then
    if ! echo "$value" | grep -qE "$validation_pattern"; then
      echo -e "${RED}✗ CRITICAL: $key has invalid format${NC}"
      echo -e "  Expected pattern: $validation_pattern"
      return 1
    fi
  fi

  echo -e "${GREEN}✓ $key present and valid${NC}"
  return 0
}

# Function to check optional secret
check_optional_secret() {
  local key=$1

  local value
  value=$(kubectl get secret rsolv-secrets -n "$NAMESPACE" -o jsonpath="{.data.$key}" 2>/dev/null | base64 -d 2>/dev/null || echo "")

  if [ -z "$value" ]; then
    echo -e "${YELLOW}⚠ WARNING: $key is not set (optional but recommended)${NC}"
    return 0
  fi

  echo -e "${GREEN}✓ $key present${NC}"
  return 0
}

ERRORS=0

echo "Checking required secrets..."
echo ""

# Check DATABASE_URL
if ! check_required_secret "DATABASE_URL" "^postgresql://"; then
  ERRORS=$((ERRORS + 1))
fi

# Check SECRET_KEY_BASE (64 hex characters)
if ! check_required_secret "SECRET_KEY_BASE" "^[a-fA-F0-9]{64}$"; then
  ERRORS=$((ERRORS + 1))
fi

# Check STRIPE_API_KEY
if [ "$NAMESPACE" = "rsolv-production" ]; then
  if ! check_required_secret "STRIPE_API_KEY" "^sk_live_"; then
    ERRORS=$((ERRORS + 1))
  fi
else
  if ! check_required_secret "STRIPE_API_KEY" "^sk_test_"; then
    ERRORS=$((ERRORS + 1))
  fi
fi

# Check STRIPE_WEBHOOK_SECRET (CRITICAL)
if ! check_required_secret "STRIPE_WEBHOOK_SECRET" "^whsec_"; then
  echo -e "${RED}  ⚠️  Pro subscriptions will NOT work without this!${NC}"
  echo -e "${RED}  ⚠️  Customers will pay \$599 but receive 0 credits${NC}"
  echo -e "${RED}  See: VK task ed10776b-524f-4a62-9c3a-413433adfb9d${NC}"
  ERRORS=$((ERRORS + 1))
fi

echo ""
echo "Checking optional secrets..."
echo ""

check_optional_secret "ANTHROPIC_API_KEY"
check_optional_secret "OPENAI_API_KEY"
check_optional_secret "POSTMARK_API_KEY"
check_optional_secret "SENTRY_DSN"

echo ""
echo "========================================"
if [ $ERRORS -eq 0 ]; then
  echo -e "${GREEN}✓ All checks passed!${NC}"
  echo "========================================"
  exit 0
else
  echo -e "${RED}✗ $ERRORS critical error(s) found${NC}"
  echo "========================================"
  echo ""
  echo "Fix errors before deploying to production."
  exit 1
fi
