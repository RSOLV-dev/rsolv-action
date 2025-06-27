#!/bin/bash

echo "Testing Elixir parser directly..."

# Test 1: Health check
echo "Test 1: Health check"
echo '{"command": "HEALTH_CHECK"}' | elixir priv/parsers/elixir/parser.exs &
PID=$!
sleep 2
if kill -0 $PID 2>/dev/null; then
    echo "Parser seems to be hanging..."
    kill $PID
else
    wait $PID
fi

echo ""
echo "Test 2: Simple parse"
echo '{"id": 1, "code": "def test, do: :hello"}' | timeout 5 elixir priv/parsers/elixir/parser.exs

echo ""
echo "Test 3: With action field"
echo '{"id": 1, "action": "parse", "code": "def test, do: :hello"}' | timeout 5 elixir priv/parsers/elixir/parser.exs