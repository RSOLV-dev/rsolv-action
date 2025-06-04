#!/bin/bash
set -e

# Build and push Docker image
echo "Building Docker image..."
docker build -t ghcr.io/rsolv-dev/rsolv-api:latest .

echo "Pushing to GitHub Container Registry..."
docker push ghcr.io/rsolv-dev/rsolv-api:latest

# Apply Kubernetes configurations
echo "Applying Kubernetes deployments..."
kubectl apply -f k8s/

# Wait for deployment
echo "Waiting for deployment to complete..."
kubectl rollout status deployment/rsolv-api

# Show deployment status
echo "Deployment status:"
kubectl get pods -l app=rsolv-api

echo "API service deployed successfully!"
echo "API endpoint: https://api.rsolv.dev"