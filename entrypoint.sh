#!/bin/sh
set -e

# Set up node name for clustering
if [ -n "$POD_NAME" ] && [ -n "$POD_NAMESPACE" ]; then
  # In Kubernetes, use pod IP for clustering
  export RELEASE_NAME="rsolv_api"
  
  # Get the pod IP
  POD_IP=$(hostname -i)
  
  # Set the node name for distributed Erlang
  export RELEASE_DISTRIBUTION="name"
  export RELEASE_NODE="${RELEASE_NAME}@${POD_IP}"
  
  echo "Starting clustered node: ${RELEASE_NODE}"
else
  # For non-Kubernetes environments
  export RELEASE_DISTRIBUTION="sname"
  export RELEASE_NODE="rsolv_api@localhost"
  
  echo "Starting single node: ${RELEASE_NODE}"
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