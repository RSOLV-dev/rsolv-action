#!/bin/bash
set -e

# RSOLV Platform Deployment Script
# Usage: ./deploy.sh [staging|production]
#
# IMPORTANT DATABASE NOTES:
# - Production uses the existing rsolv_landing_prod database (consolidated as per RFC-037)
# - Staging uses rsolv_staging database
# - The empty rsolv_api_prod and rsolv_platform_prod databases can be cleaned up
#
# Database Configuration:
# - Production: rsolv_landing_prod (contains all web + API data post-consolidation)
# - Staging: rsolv_staging
# - Database secret must be named: rsolv-platform-db-secret

ENVIRONMENT=${1:-staging}
NAMESPACE="rsolv-${ENVIRONMENT}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
MIGRATION_TIMEOUT=${MIGRATION_TIMEOUT:-600s}  # Allow overriding timeout, default 10 minutes

if [ "$ENVIRONMENT" == "production" ]; then
    IMAGE_TAG="ghcr.io/rsolv-dev/rsolv-platform:prod-${TIMESTAMP}"
    echo "⚠️  WARNING: Deploying to PRODUCTION!"
    read -p "Are you sure? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        echo "Deployment cancelled."
        exit 1
    fi
else
    IMAGE_TAG="ghcr.io/rsolv-dev/rsolv-platform:staging-${TIMESTAMP}"
fi

echo "🚀 Deploying RSOLV Platform to ${ENVIRONMENT}"
echo "📦 Building image: ${IMAGE_TAG}"

# Build and push image
docker build -t "${IMAGE_TAG}" -t "ghcr.io/rsolv-dev/rsolv-platform:${ENVIRONMENT}" .
docker push "${IMAGE_TAG}"
docker push "ghcr.io/rsolv-dev/rsolv-platform:${ENVIRONMENT}"

echo "🔄 Running database migrations..."

# Create migration job from template
cat > /tmp/migration-job-${TIMESTAMP}.yaml <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: rsolv-migrate-${TIMESTAMP}
  namespace: ${NAMESPACE}
spec:
  ttlSecondsAfterFinished: 600  # Clean up after 10 minutes
  template:
    metadata:
      labels:
        app: rsolv-platform-migrate
    spec:
      restartPolicy: Never
      containers:
      - name: migrate
        image: ${IMAGE_TAG}
        command: ["/app/bin/rsolv", "eval", "Rsolv.Release.migrate()"]
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: rsolv-secrets
              key: database-url
        - name: DATABASE_SSL
          value: "false"
        - name: SECRET_KEY_BASE
          valueFrom:
            secretKeyRef:
              name: rsolv-secrets
              key: secret-key-base
        - name: MIX_ENV
          value: "prod"
      imagePullSecrets:
      - name: ghcr-secret
EOF

# Run migration job
kubectl apply -f /tmp/migration-job-${TIMESTAMP}.yaml

# Wait for migration to complete
echo "⏳ Waiting for migrations to complete (timeout: ${MIGRATION_TIMEOUT})..."
kubectl wait --for=condition=complete job/rsolv-migrate-${TIMESTAMP} -n ${NAMESPACE} --timeout=${MIGRATION_TIMEOUT}

# Check migration logs
echo "📋 Migration logs:"
kubectl logs job/rsolv-migrate-${TIMESTAMP} -n ${NAMESPACE}

# Update deployment
echo "🔄 Updating deployment..."
kubectl set image deployment/${ENVIRONMENT}-rsolv-platform rsolv-platform=${IMAGE_TAG} -n ${NAMESPACE}

# Wait for rollout
echo "⏳ Waiting for rollout to complete..."
kubectl rollout status deployment/${ENVIRONMENT}-rsolv-platform -n ${NAMESPACE}

# Run health check
echo "🏥 Running health check..."
POD=$(kubectl get pods -n ${NAMESPACE} -l app=${ENVIRONMENT}-rsolv-platform -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n ${NAMESPACE} $POD -- wget -qO- http://localhost:4000/health | jq .

echo "✅ Deployment complete!"
echo "🌐 Environment: ${ENVIRONMENT}"
echo "🏷️  Image: ${IMAGE_TAG}"

# Cleanup
rm -f /tmp/migration-job-${TIMESTAMP}.yaml