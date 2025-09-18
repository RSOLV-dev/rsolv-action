#!/bin/bash

# Update production secrets with available API keys

echo "Updating production secrets with API keys..."

# Kit.com credentials from .envrc
kubectl patch secret rsolv-secrets -n rsolv-production --type='json' \
  -p='[
    {"op": "replace", "path": "/data/kit-api-key", "value": "'$(echo -n "RmBFh8z9WAL_Wfs3TWpgIw" | base64 -w 0)'"},
    {"op": "replace", "path": "/data/kit-form-id", "value": "'$(echo -n "7995546" | base64 -w 0)'"},
    {"op": "replace", "path": "/data/kit-ea-tag-id", "value": "'$(echo -n "7700607" | base64 -w 0)'"}
  ]' 2>/dev/null || {
    # If the keys don't exist, add them
    kubectl patch secret rsolv-secrets -n rsolv-production --type='json' \
      -p='[
        {"op": "add", "path": "/data/kit-api-key", "value": "'$(echo -n "RmBFh8z9WAL_Wfs3TWpgIw" | base64 -w 0)'"},
        {"op": "add", "path": "/data/kit-form-id", "value": "'$(echo -n "7995546" | base64 -w 0)'"},
        {"op": "add", "path": "/data/kit-ea-tag-id", "value": "'$(echo -n "7700607" | base64 -w 0)'"}
      ]'
}

echo "✅ Kit.com credentials updated"

# AI provider keys from environment
kubectl patch secret rsolv-secrets -n rsolv-production --type='json' \
  -p='[
    {"op": "replace", "path": "/data/anthropic-api-key", "value": "'$(echo -n "$ANTHROPIC_API_KEY" | base64 -w 0)'"},
    {"op": "replace", "path": "/data/openai-api-key", "value": "'$(echo -n "$OPENAI_API_KEY" | base64 -w 0)'"}
  ]'

echo "✅ AI provider API keys updated"

echo ""
echo "Restarting production deployment to apply changes..."
kubectl rollout restart deployment/rsolv-platform -n rsolv-production

echo ""
echo "Waiting for rollout to complete..."
kubectl rollout status deployment/rsolv-platform -n rsolv-production

echo ""
echo "✅ Production secrets updated and deployment restarted!"
echo "The credential vending system should now provide actual API keys."