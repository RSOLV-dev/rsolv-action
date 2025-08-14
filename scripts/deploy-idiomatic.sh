#!/bin/bash
set -euo pipefail

# RSOLV Platform Idiomatic Deployment Script
# Uses Phoenix/Elixir best practices for deployments

ENVIRONMENT=${1:-staging}
NAMESPACE="rsolv-${ENVIRONMENT}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Validate environment
if [[ ! "$ENVIRONMENT" =~ ^(staging|production)$ ]]; then
    error "Invalid environment: $ENVIRONMENT. Must be 'staging' or 'production'"
    exit 1
fi

# Production safety check
if [ "$ENVIRONMENT" == "production" ]; then
    warning "You are about to deploy to PRODUCTION!"
    echo -n "Type 'deploy to production' to confirm: "
    read -r confirmation
    if [ "$confirmation" != "deploy to production" ]; then
        error "Deployment cancelled"
        exit 1
    fi
fi

# Configuration
IMAGE_BASE="ghcr.io/rsolv-dev/rsolv-platform"
IMAGE_TAG="${IMAGE_BASE}:${ENVIRONMENT}-${TIMESTAMP}"
IMAGE_LATEST="${IMAGE_BASE}:${ENVIRONMENT}"

log "Starting deployment to ${ENVIRONMENT}"
log "Image: ${IMAGE_TAG}"

# Step 1: Run tests locally first
log "Running tests..."
if ! MIX_ENV=test mix test; then
    error "Tests failed. Aborting deployment."
    exit 1
fi
success "Tests passed"

# Step 2: Check for pending migrations
log "Checking for pending migrations..."
PENDING_MIGRATIONS=$(MIX_ENV=prod mix ecto.migrations | grep -c "down" || true)
if [ "$PENDING_MIGRATIONS" -gt 0 ]; then
    log "Found $PENDING_MIGRATIONS pending migrations"
else
    log "No pending migrations"
fi

# Step 3: Build release
log "Building release..."
if ! MIX_ENV=prod mix release --overwrite; then
    error "Release build failed"
    exit 1
fi
success "Release built"

# Step 4: Build and push Docker image
log "Building Docker image..."
if ! docker build \
    --build-arg MIX_ENV=prod \
    --tag "${IMAGE_TAG}" \
    --tag "${IMAGE_LATEST}" \
    "${PROJECT_ROOT}"; then
    error "Docker build failed"
    exit 1
fi
success "Docker image built"

log "Pushing Docker image..."
docker push "${IMAGE_TAG}"
docker push "${IMAGE_LATEST}"
success "Docker image pushed"

# Step 5: Run pre-deployment health check
log "Running pre-deployment health check..."
CURRENT_HEALTH=$(kubectl exec -n "${NAMESPACE}" \
    "$(kubectl get pods -n "${NAMESPACE}" -l app="${ENVIRONMENT}-rsolv-platform" -o jsonpath='{.items[0].metadata.name}')" \
    -- /app/bin/rsolv eval "Rsolv.ReleaseTasks.health_check" 2>/dev/null || echo "FAILED")

if [[ "$CURRENT_HEALTH" == "FAILED" ]]; then
    warning "Current deployment health check failed (this is expected for first deployment)"
fi

# Step 6: Run database migrations using Job
if [ "$PENDING_MIGRATIONS" -gt 0 ] || [ "$ENVIRONMENT" == "staging" ]; then
    log "Running database migrations..."
    
    # Create migration job
    cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: migrate-${TIMESTAMP}
  namespace: ${NAMESPACE}
spec:
  ttlSecondsAfterFinished: 300
  backoffLimit: 2
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: migrate
        image: ${IMAGE_TAG}
        command: ["/app/bin/rsolv", "eval", "Rsolv.ReleaseTasks.setup"]
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: rsolv-platform-db-secret
              key: database-url
        - name: SECRET_KEY_BASE
          valueFrom:
            secretKeyRef:
              name: phoenix-secrets
              key: SECRET_KEY_BASE
        - name: MIX_ENV
          value: "prod"
        - name: POOL_SIZE
          value: "2"
      imagePullSecrets:
      - name: ghcr-secret
EOF

    # Wait for migration job to complete
    log "Waiting for migrations to complete..."
    if kubectl wait --for=condition=complete "job/migrate-${TIMESTAMP}" -n "${NAMESPACE}" --timeout=300s; then
        success "Migrations completed"
        
        # Show migration logs
        log "Migration output:"
        kubectl logs "job/migrate-${TIMESTAMP}" -n "${NAMESPACE}"
    else
        error "Migration job failed"
        kubectl logs "job/migrate-${TIMESTAMP}" -n "${NAMESPACE}"
        exit 1
    fi
fi

# Step 7: Deploy new version
log "Deploying new version..."
kubectl set image "deployment/${ENVIRONMENT}-rsolv-platform" \
    "rsolv-platform=${IMAGE_TAG}" \
    -n "${NAMESPACE}"

# Step 8: Monitor rollout
log "Monitoring rollout..."
if kubectl rollout status "deployment/${ENVIRONMENT}-rsolv-platform" -n "${NAMESPACE}" --timeout=600s; then
    success "Rollout completed successfully"
else
    error "Rollout failed"
    log "Rolling back..."
    kubectl rollout undo "deployment/${ENVIRONMENT}-rsolv-platform" -n "${NAMESPACE}"
    exit 1
fi

# Step 9: Post-deployment verification
log "Running post-deployment verification..."
sleep 10  # Give the app time to stabilize

# Check health endpoint
HEALTH_RESPONSE=$(curl -s -w "\\n%{http_code}" "https://${ENVIRONMENT}.rsolv.net/health" || echo "FAILED")
HTTP_CODE=$(echo "$HEALTH_RESPONSE" | tail -n1)
HEALTH_JSON=$(echo "$HEALTH_RESPONSE" | head -n-1)

if [[ "$HTTP_CODE" == "200" ]]; then
    success "Health check passed"
    echo "$HEALTH_JSON" | jq . || echo "$HEALTH_JSON"
else
    error "Health check failed with HTTP code: $HTTP_CODE"
    warning "Response: $HEALTH_JSON"
fi

# Check if we can reach the homepage
if curl -s -o /dev/null -w "%{http_code}" "https://${ENVIRONMENT}.rsolv.net/" | grep -q "200"; then
    success "Homepage is accessible"
else
    error "Homepage is not accessible"
fi

# Step 10: Cleanup old resources
log "Cleaning up old resources..."
kubectl delete jobs -n "${NAMESPACE}" -l "app=rsolv-platform,component=migration" --field-selector status.successful=1 2>/dev/null || true

# Summary
echo ""
success "Deployment completed!"
echo ""
echo "Deployment Summary:"
echo "  Environment: ${ENVIRONMENT}"
echo "  Namespace: ${NAMESPACE}" 
echo "  Image: ${IMAGE_TAG}"
echo "  URL: https://${ENVIRONMENT}.rsolv.net/"
echo ""

# Optionally open the site
if command -v xdg-open &> /dev/null; then
    echo -n "Open site in browser? (y/n): "
    read -r open_browser
    if [[ "$open_browser" == "y" ]]; then
        xdg-open "https://${ENVIRONMENT}.rsolv.net/"
    fi
fi