#!/bin/bash
# Test script for Ollama AI provider

# Show usage instructions
echo "🚀 Running Ollama AI provider test"
echo ""
echo "This script tests the Ollama integration with local or remote Ollama servers."
echo ""
echo "Environment variables you can set:"
echo "  OLLAMA_MODEL    - Specify which model to use (default: deepseek-r1:14b)"
echo "  OLLAMA_API_KEY  - For remote servers, use format: http://server:11434/api:token"
echo ""

# Check if Ollama is installed
if ! command -v ollama >/dev/null 2>&1; then
  echo "⚠️ Ollama CLI not found. You may need to install it:"
  echo "  curl -fsSL https://ollama.com/install.sh | sh"
  echo ""
  echo "Continuing with test assuming server is already running..."
else
  echo "✅ Ollama CLI detected: $(ollama --version)"
  
  # Check if Ollama server is running
  if ! curl -s http://localhost:11434/api/version >/dev/null 2>&1; then
    echo "⚠️ Ollama server not running. Starting it now..."
    # Start Ollama server in background
    ollama serve >/dev/null 2>&1 &
    OLLAMA_PID=$!
    
    # Give it a moment to start
    echo "Waiting for Ollama server to start..."
    sleep 3
    
    # Verify it started
    if ! curl -s http://localhost:11434/api/version >/dev/null 2>&1; then
      echo "❌ Failed to start Ollama server. Please start it manually:"
      echo "  ollama serve"
      exit 1
    else
      echo "✅ Ollama server started"
    fi
  else
    echo "✅ Ollama server already running"
  fi
  
  # Check if the model is available
  MODEL=${OLLAMA_MODEL:-deepseek-r1:14b}
  if ! ollama list | grep -q "$MODEL"; then
    echo "⚠️ Model '$MODEL' not found. Pulling it now..."
    ollama pull $MODEL
  else
    echo "✅ Model '$MODEL' is available"
  fi
fi

# Run the test
echo ""
echo "Starting Ollama test with model ${OLLAMA_MODEL:-deepseek-r1:14b}..."
# Set NODE_ENV to development for better error handling with fallbacks
NODE_ENV=development bun run test-ollama.js

# If we started an Ollama server, keep it running
if [ -n "$OLLAMA_PID" ]; then
  echo ""
  echo "Ollama server is still running (PID $OLLAMA_PID)."
  echo "You can stop it with: kill $OLLAMA_PID"
fi