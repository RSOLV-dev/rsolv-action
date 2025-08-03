#!/bin/sh
set -e

# GitHub Actions mounts the workspace at /github/workspace
# We need to run from there to have access to the git repository
if [ -d "/github/workspace" ]; then
  cd /github/workspace
  echo "Running from GitHub workspace: $(pwd)"
  
  # Fix git ownership issue in Docker container
  # GitHub Actions runs as a different user than the container
  git config --global --add safe.directory /github/workspace
  echo "Added /github/workspace as safe directory for git"
else
  # Fallback for local testing
  cd /app
  echo "Running from app directory: $(pwd)"
fi

# Run the action using the built output from /app
exec bun run /app/dist/index.js
