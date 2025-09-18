#!/bin/bash

# Test clustering locally with multiple nodes

echo "Testing RSOLV API clustering locally..."
echo "======================================="

# Set a common cookie
export RELEASE_COOKIE="test-clustering-cookie"

# Function to start a node
start_node() {
  local node_num=$1
  local port=$((4000 + node_num))
  
  echo "Starting node $node_num on port $port..."
  
  PORT=$port \
  RELEASE_NODE_NAME="rsolv_api_$node_num@127.0.0.1" \
  RELEASE_DISTRIBUTION="name" \
  iex --name "rsolv_api_$node_num@127.0.0.1" \
      --cookie "$RELEASE_COOKIE" \
      -S mix phx.server &
}

# Instructions
echo ""
echo "This script helps test clustering locally."
echo "It will show you how to start multiple nodes that can connect to each other."
echo ""
echo "To test clustering:"
echo ""
echo "1. In terminal 1, start the first node:"
echo "   PORT=4001 RELEASE_NODE_NAME='rsolv_api_1@127.0.0.1' RELEASE_DISTRIBUTION=name iex --name 'rsolv_api_1@127.0.0.1' --cookie 'test-cookie' -S mix phx.server"
echo ""
echo "2. In terminal 2, start the second node:"
echo "   PORT=4002 RELEASE_NODE_NAME='rsolv_api_2@127.0.0.1' RELEASE_DISTRIBUTION=name iex --name 'rsolv_api_2@127.0.0.1' --cookie 'test-cookie' -S mix phx.server"
echo ""
echo "3. In either IEx console, check connected nodes:"
echo "   Node.list()"
echo ""
echo "4. Connect nodes manually if needed:"
echo "   Node.connect(:'rsolv_api_2@127.0.0.1')"
echo ""
echo "5. Test PubSub across nodes:"
echo "   Phoenix.PubSub.broadcast(RSOLV.PubSub, \"test\", {:hello, node()})"
echo ""
echo "6. Check the health endpoints:"
echo "   curl http://localhost:4001/health | jq .clustering"
echo "   curl http://localhost:4002/health | jq .clustering"
echo ""