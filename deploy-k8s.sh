#!/bin/bash
set -e

echo "=== RSOLV API Kubernetes Deployment ==="
echo ""

# Check if we have the required API keys
if [ -z "$ANTHROPIC_API_KEY" ] && [ -z "$OPENROUTER_API_KEY" ]; then
    echo "WARNING: No AI provider keys found in environment!"
    echo "Set at least one of: ANTHROPIC_API_KEY, OPENROUTER_API_KEY"
    echo ""
    echo "Example:"
    echo "  export ANTHROPIC_API_KEY='your-key-here'"
    echo "  export OPENROUTER_API_KEY='your-key-here'"
    echo ""
    read -p "Continue with mock keys? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
    ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-mock-anthropic-key}"
    OPENROUTER_API_KEY="${OPENROUTER_API_KEY:-mock-openrouter-key}"
fi

OPENAI_API_KEY="${OPENAI_API_KEY:-mock-openai-key}"

# Generate secure keys
SECRET_KEY_BASE=$(openssl rand -hex 64)
LIVE_VIEW_SALT=$(openssl rand -hex 32)
DB_PASSWORD=$(openssl rand -hex 16)

# Create secrets with actual values
cat > k8s/secrets.yaml << EOF
apiVersion: v1
kind: Secret
metadata:
  name: postgres-secrets
  namespace: default
type: Opaque
stringData:
  password: "$DB_PASSWORD"
---
apiVersion: v1
kind: Secret
metadata:
  name: rsolv-api-secrets
  namespace: default
type: Opaque
stringData:
  database-url: "postgres://rsolv:$DB_PASSWORD@postgres:5432/rsolv_api_prod"
  secret-key-base: "$SECRET_KEY_BASE"
  anthropic-api-key: "$ANTHROPIC_API_KEY"
  openai-api-key: "$OPENAI_API_KEY"
  openrouter-api-key: "$OPENROUTER_API_KEY"
  sendgrid-api-key: "${SENDGRID_API_KEY:-dummy-sendgrid-key}"
  live-view-salt: "$LIVE_VIEW_SALT"
EOF

echo "1. Deploying PostgreSQL..."
kubectl apply -f k8s/postgres.yaml

echo ""
echo "2. Waiting for PostgreSQL to be ready..."
kubectl wait --for=condition=ready pod -l app=postgres --timeout=60s

echo ""
echo "3. Applying secrets..."
kubectl apply -f k8s/secrets.yaml

echo ""
echo "4. Building Docker image..."
docker build -t ghcr.io/rsolv-dev/rsolv-api:latest .

echo ""
echo "5. Pushing to GitHub Container Registry..."
echo "   (Make sure you're logged in with: docker login ghcr.io)"
docker push ghcr.io/rsolv-dev/rsolv-api:latest || {
    echo "Push failed. Using local image for now."
    # Update deployment to use local image
    sed -i.bak 's|ghcr.io/rsolv-dev/rsolv-api:latest|rsolv-api:latest|' k8s/deployment.yaml
    sed -i.bak 's|imagePullPolicy: Always|imagePullPolicy: IfNotPresent|' k8s/deployment.yaml
}

echo ""
echo "6. Deploying RSOLV API..."
kubectl apply -f k8s/deployment.yaml

echo ""
echo "7. Waiting for deployment..."
kubectl rollout status deployment/rsolv-api

echo ""
echo "8. Running database migrations..."
POD=$(kubectl get pod -l app=rsolv-api -o jsonpath="{.items[0].metadata.name}")
kubectl exec -it $POD -- bin/rsolv_api eval "RSOLV.Release.migrate" || {
    echo "Note: Migration command not found. This might be expected for the simple API."
}

echo ""
echo "=== Deployment Complete ==="
echo ""
echo "Service Status:"
kubectl get pods -l app=rsolv-api
echo ""
echo "To check logs:"
echo "  kubectl logs -l app=rsolv-api --tail=50"
echo ""
echo "To test the API:"
echo "  kubectl port-forward service/rsolv-api 4000:80"
echo "  curl http://localhost:4000/health"
echo ""

# Get the internal API key if using simple-api.js
if kubectl logs -l app=rsolv-api --tail=100 | grep -q "Internal API Key"; then
    echo "Internal API Key:"
    kubectl logs -l app=rsolv-api --tail=100 | grep "Internal API Key"
    echo ""
    echo "Update GitHub secrets with:"
    echo "  gh secret set RSOLV_API_KEY --body 'the-key-above'"
fi

# Clean up
rm -f k8s/deployment.yaml.bak