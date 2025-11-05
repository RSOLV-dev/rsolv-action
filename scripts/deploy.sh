#!/bin/bash
# RSOLV Platform Deployment Script
#
# DEPRECATED: This script is deprecated in favor of the unified deployment script
# in the RSOLV-infrastructure repository.
#
# Usage: ./deploy.sh [staging|production]
#
# This script now delegates to the infrastructure repo's deployment script,
# which is the single source of truth for all deployments.

set -e

ENVIRONMENT=${1:-staging}
INFRASTRUCTURE_REPO="${INFRASTRUCTURE_REPO:-$HOME/dev/rsolv/RSOLV-infrastructure}"

echo "════════════════════════════════════════════════════════════════"
echo "⚠️  NOTICE: Using unified deployment from RSOLV-infrastructure"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "This script delegates to the infrastructure repository's"
echo "deployment script, which is the single source of truth for"
echo "all RSOLV deployments."
echo ""
echo "Infrastructure repo: $INFRASTRUCTURE_REPO"
echo "Environment: $ENVIRONMENT"
echo ""

# Check if infrastructure repo exists
if [[ ! -d "$INFRASTRUCTURE_REPO" ]]; then
    echo "❌ Error: Infrastructure repository not found at $INFRASTRUCTURE_REPO"
    echo ""
    echo "Please either:"
    echo "  1. Clone the infrastructure repo to $INFRASTRUCTURE_REPO"
    echo "  2. Set INFRASTRUCTURE_REPO environment variable to the correct path"
    echo ""
    echo "Example:"
    echo "  git clone https://github.com/RSOLV-dev/rsolv-infrastructure.git $INFRASTRUCTURE_REPO"
    echo "  INFRASTRUCTURE_REPO=/path/to/rsolv-infrastructure ./scripts/deploy.sh $ENVIRONMENT"
    exit 1
fi

DEPLOY_SCRIPT="$INFRASTRUCTURE_REPO/scripts/deploy-unified-platform.sh"

if [[ ! -f "$DEPLOY_SCRIPT" ]]; then
    echo "❌ Error: Deployment script not found at $DEPLOY_SCRIPT"
    exit 1
fi

# Delegate to infrastructure deployment script
echo "🚀 Delegating to: $DEPLOY_SCRIPT"
echo ""
exec "$DEPLOY_SCRIPT" "$ENVIRONMENT"
