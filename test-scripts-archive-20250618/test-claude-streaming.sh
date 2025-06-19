#!/bin/bash
# Simple shell script to test Claude CLI streaming

echo "Testing Claude CLI streaming capabilities..."

# Set timeout (default 60 seconds)
TIMEOUT=${1:-60}

echo "Using timeout: ${TIMEOUT}s"
echo "Testing with various output formats..."

# Test 1: Default output
echo -e "\n\033[1;34mTest 1: Default output\033[0m"
echo "echo 'Say hello briefly' | timeout ${TIMEOUT}s claude --print"
echo "Say hello briefly" | timeout ${TIMEOUT}s claude --print

# Test 2: JSON output format
echo -e "\n\033[1;34mTest 2: JSON output format\033[0m"
echo "echo 'Say hello briefly in JSON' | timeout ${TIMEOUT}s claude --print --output-format json"
echo "Say hello briefly in JSON" | timeout ${TIMEOUT}s claude --print --output-format json

# Test 3: Stream JSON output format
echo -e "\n\033[1;34mTest 3: Stream JSON output format\033[0m"
echo "echo 'Say hello briefly in streaming format' | timeout ${TIMEOUT}s claude --print --output-format stream-json"
echo "Say hello briefly in streaming format" | timeout ${TIMEOUT}s claude --print --output-format stream-json

# Test 4: Verbose mode
echo -e "\n\033[1;34mTest 4: Verbose mode\033[0m"
echo "echo 'Say hello briefly with verbose output' | timeout ${TIMEOUT}s claude --print --verbose"
echo "Say hello briefly with verbose output" | timeout ${TIMEOUT}s claude --print --verbose

echo -e "\n\033[1;32mTesting complete!\033[0m"