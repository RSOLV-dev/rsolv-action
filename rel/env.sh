#!/bin/sh

# Configure clustering for Kubernetes environment
if [ -n "$POD_IP" ]; then
  # Enable distributed Erlang with long names for Kubernetes
  export RELEASE_DISTRIBUTION=name
  export RELEASE_NODE=rsolv@${POD_IP}
  echo "Kubernetes clustering enabled: ${RELEASE_NODE}"
else
  # For local development/testing
  export RELEASE_DISTRIBUTION=sname
  export RELEASE_NODE=rsolv@localhost
  echo "Local development mode: ${RELEASE_NODE}"
fi