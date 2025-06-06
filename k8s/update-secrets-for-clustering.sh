#!/bin/bash

# Script to add Erlang cookie to existing secrets

# Generate a secure cookie if not provided
if [ -z "$ERLANG_COOKIE" ]; then
  ERLANG_COOKIE=$(openssl rand -hex 32)
  echo "Generated Erlang cookie: $ERLANG_COOKIE"
fi

# Check if the secret exists
if kubectl get secret rsolv-api-secrets > /dev/null 2>&1; then
  echo "Updating existing secret with erlang-cookie..."
  
  # Get the current secret data
  kubectl get secret rsolv-api-secrets -o json > temp-secret.json
  
  # Add the erlang-cookie to the data section
  ENCODED_COOKIE=$(echo -n "$ERLANG_COOKIE" | base64)
  
  # Update the secret
  kubectl patch secret rsolv-api-secrets --type='json' -p='[{"op": "add", "path": "/data/erlang-cookie", "value": "'$ENCODED_COOKIE'"}]'
  
  # Clean up
  rm -f temp-secret.json
  
  echo "Secret updated successfully!"
else
  echo "Secret rsolv-api-secrets not found. Please create it first."
  exit 1
fi

echo ""
echo "To deploy with clustering enabled, run:"
echo "kubectl apply -f k8s/deployment-with-clustering.yaml"