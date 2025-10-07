#!/bin/sh

# Configure clustering for Kubernetes environment
if [ -n "$POD_IP" ]; then
  # Enable distributed Erlang with long names for Kubernetes
  export RELEASE_DISTRIBUTION=name
  export RELEASE_NODE=rsolv@${POD_IP}
else
  # For local development/testing
  export RELEASE_DISTRIBUTION=sname
  export RELEASE_NODE=rsolv@localhost
fi