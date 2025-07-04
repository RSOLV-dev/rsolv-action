#!/bin/bash
set -e

# RFC-037 Consolidated Service Deployment Script
# Supports both staging and production deployments

# Default to staging environment
ENVIRONMENT=${1:-staging}
NAMESPACE="rsolv-${ENVIRONMENT}"

# Generate timestamped tag for production, use environment name for staging
if [ "$ENVIRONMENT" = "production" ]; then
    TAG=$(date +%Y%m%d-%H%M%S)
else
    TAG="$ENVIRONMENT"
fi

IMAGE_NAME="ghcr.io/rsolv-dev/rsolv-platform:${TAG}"

echo "🚀 RFC-037 Consolidated Service Deployment"
echo "Environment: $ENVIRONMENT"
echo "Namespace: $NAMESPACE"
echo "Image: $IMAGE_NAME"
echo ""

# Build and push Docker image
echo "Building consolidated Docker image..."
DOCKER_HOST=10.5.0.5 docker build -t "$IMAGE_NAME" .

echo "Pushing to GitHub Container Registry..."
DOCKER_HOST=10.5.0.5 docker push "$IMAGE_NAME"

# Apply Kubernetes configurations
echo "Applying Kubernetes deployments to $NAMESPACE..."
if [ -d "../RSOLV-infrastructure/environments/$ENVIRONMENT/platform" ]; then
    kubectl apply -k "../RSOLV-infrastructure/environments/$ENVIRONMENT/platform"
else
    echo "⚠️  Using local k8s/ configs (infrastructure configs not found)"
    kubectl apply -f k8s/ -n "$NAMESPACE"
fi

# Update deployment image
echo "Updating deployment image..."
kubectl set image deployment/rsolv-platform rsolv-platform="$IMAGE_NAME" -n "$NAMESPACE"

# Wait for deployment
echo "Waiting for deployment to complete..."
kubectl rollout status deployment/rsolv-platform -n "$NAMESPACE"

# Show deployment status
echo "Deployment status:"
kubectl get pods -l app=rsolv-platform -n "$NAMESPACE"

# Test health endpoints
echo ""
echo "Testing health endpoints..."
POD_NAME=$(kubectl get pods -l app=rsolv-platform -n "$NAMESPACE" -o name | head -1)
if [ -n "$POD_NAME" ]; then
    echo "Web health check:"
    kubectl exec -n "$NAMESPACE" "$POD_NAME" -- wget -qO- http://localhost:4000/health || echo "❌ Web health check failed"
    
    echo "API health check:"
    kubectl exec -n "$NAMESPACE" "$POD_NAME" -- wget -qO- http://localhost:4000/api/health || echo "❌ API health check failed"
    
    echo "Database connectivity:"
    kubectl exec -n "$NAMESPACE" "$POD_NAME" -- bin/rsolv rpc 'Rsolv.Repo.query("SELECT 1")' || echo "❌ Database check failed"
fi

echo ""
echo "🎉 Service deployed successfully!"
echo "Environment: $ENVIRONMENT"
if [ "$ENVIRONMENT" = "staging" ]; then
    echo "Endpoints: https://rsolv-staging.com and https://api-staging.rsolv.dev"
else
    echo "Endpoints: https://rsolv.dev and https://api.rsolv.dev"
fi
echo ""
echo "Next steps:"
echo "1. Test web interface and API endpoints"
echo "2. Verify all functionality works as expected"
echo "3. Check logs: kubectl logs -l app=rsolv-platform -n $NAMESPACE"