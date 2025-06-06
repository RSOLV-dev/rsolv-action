#!/bin/sh
set -e

# Set up node name for clustering
if [ -n "$POD_NAME" ] && [ -n "$POD_NAMESPACE" ]; then
  # In Kubernetes, use pod name and namespace
  export RELEASE_NODE="${POD_NAME}"
  export RELEASE_NAME="rsolv_api"
  
  # Get the pod IP
  POD_IP=$(hostname -i)
  
  # Set the node name and cookie
  export RELEASE_DISTRIBUTION="name"
  export RELEASE_NODE_NAME="${RELEASE_NAME}@${POD_IP}"
  
  echo "Starting node: ${RELEASE_NODE_NAME}"
else
  # For non-Kubernetes environments
  export RELEASE_DISTRIBUTION="sname"
  export RELEASE_NODE_NAME="rsolv_api@localhost"
fi

# Set cookie if provided
if [ -n "$RELEASE_COOKIE" ]; then
  export RELEASE_COOKIE="${RELEASE_COOKIE}"
else
  # Use a default cookie for development
  export RELEASE_COOKIE="rsolv-api-secret-cookie"
fi

# The idiomatic approach: Run migrations in a separate step before deployment
# This script just starts the app

exec bin/rsolv_api start