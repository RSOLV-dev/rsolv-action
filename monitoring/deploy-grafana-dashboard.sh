#!/bin/bash

# Deploy Grafana dashboard for false positive cache metrics
# Usage: ./deploy-grafana-dashboard.sh [staging|production]

ENV=${1:-staging}

if [ "$ENV" != "staging" ] && [ "$ENV" != "production" ]; then
    echo "Usage: $0 [staging|production]"
    exit 1
fi

echo "=== Deploying Grafana Dashboard to $ENV ==="

# Set environment-specific variables
if [ "$ENV" = "staging" ]; then
    GRAFANA_URL="https://grafana.rsolv-staging.com"
    GRAFANA_API_KEY="${GRAFANA_STAGING_API_KEY}"
    DASHBOARD_FILE="false-positive-cache-staging.json"
    NAMESPACE="rsolv-staging"
else
    GRAFANA_URL="https://grafana.rsolv.dev"
    GRAFANA_API_KEY="${GRAFANA_PROD_API_KEY}"
    DASHBOARD_FILE="false-positive-cache-prod.json"
    NAMESPACE="rsolv-production"
fi

if [ -z "$GRAFANA_API_KEY" ]; then
    echo "Error: GRAFANA_${ENV^^}_API_KEY environment variable not set"
    echo "Please set it with: export GRAFANA_${ENV^^}_API_KEY=your-api-key"
    exit 1
fi

# Check if dashboard file exists
DASHBOARD_PATH="$(dirname "$0")/grafana-dashboards/$DASHBOARD_FILE"
if [ ! -f "$DASHBOARD_PATH" ]; then
    echo "Error: Dashboard file not found: $DASHBOARD_PATH"
    
    # If production dashboard doesn't exist, copy from staging
    if [ "$ENV" = "production" ] && [ -f "$(dirname "$0")/grafana-dashboards/false-positive-cache-staging.json" ]; then
        echo "Creating production dashboard from staging template..."
        sed 's/"staging"/"production"/g; s/staging/production/g' \
            "$(dirname "$0")/grafana-dashboards/false-positive-cache-staging.json" \
            > "$DASHBOARD_PATH"
        echo "Production dashboard created at: $DASHBOARD_PATH"
    else
        exit 1
    fi
fi

# Deploy dashboard via Grafana API
echo "Deploying dashboard to $GRAFANA_URL..."
RESPONSE=$(curl -s -X POST \
    -H "Authorization: Bearer $GRAFANA_API_KEY" \
    -H "Content-Type: application/json" \
    -d @"$DASHBOARD_PATH" \
    "$GRAFANA_URL/api/dashboards/db")

if echo "$RESPONSE" | grep -q '"status":"success"'; then
    echo "✅ Dashboard deployed successfully!"
    DASHBOARD_URL=$(echo "$RESPONSE" | jq -r '.url')
    echo "Dashboard URL: $GRAFANA_URL$DASHBOARD_URL"
else
    echo "❌ Failed to deploy dashboard"
    echo "Response: $RESPONSE"
    exit 1
fi

# Also ensure Prometheus is configured to scrape metrics
echo ""
echo "=== Verifying Prometheus Configuration ==="
kubectl get configmap prometheus-config -n "$NAMESPACE" -o yaml | grep -q "rsolv_cache" || {
    echo "⚠️  Warning: Prometheus may not be configured to scrape cache metrics"
    echo "Add the following to your Prometheus scrape configs:"
    echo ""
    cat <<EOF
  - job_name: 'rsolv-cache-metrics'
    kubernetes_sd_configs:
    - role: pod
      namespaces:
        names:
        - $NAMESPACE
    relabel_configs:
    - source_labels: [__meta_kubernetes_pod_label_app]
      action: keep
      regex: rsolv-platform
    - source_labels: [__meta_kubernetes_pod_container_port_name]
      action: keep
      regex: metrics
EOF
}

echo ""
echo "=== Next Steps ==="
echo "1. Access dashboard at: $GRAFANA_URL/d/fp-cache-$ENV"
echo "2. Verify metrics are flowing (may take 2-3 minutes)"
echo "3. Set up alerts for:"
echo "   - Cache hit rate < 70%"
echo "   - Response time p95 > 100ms"
echo "   - Cache memory > 1GB"
echo ""
echo "To test metrics generation:"
echo "  cd scripts/cache-testing"
echo "  ./simple-load-test.sh"