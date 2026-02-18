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

# --- Mise runtime cache restore (RFC-105) ---
# actions/cache@v4 on the host populates .mise-cache/ before the container starts.
# We copy cached installs into the default mise data dir so `mise install` is a no-op.
MISE_CACHE_PATH="/github/workspace/.mise-cache"
MISE_INSTALL_PATH="${MISE_DATA_DIR:-${HOME:-/root}/.local/share/mise}"

if [ -d "$MISE_CACHE_PATH/installs" ]; then
  echo "[RSOLV] Restoring cached mise runtimes..."
  mkdir -p "$MISE_INSTALL_PATH/installs"
  cp -a "$MISE_CACHE_PATH/installs/"* "$MISE_INSTALL_PATH/installs/" 2>/dev/null || true
  echo "[RSOLV] Restored runtimes: $(ls "$MISE_INSTALL_PATH/installs/" 2>/dev/null | tr '\n' ' ')"
fi

# Persist mise installs back to workspace cache on exit (for actions/cache to save)
persist_mise_cache() {
  if [ -d "$MISE_INSTALL_PATH/installs" ] && [ -d "/github/workspace" ]; then
    echo "[RSOLV] Persisting mise runtimes to cache..."
    mkdir -p "$MISE_CACHE_PATH/installs"
    cp -a "$MISE_INSTALL_PATH/installs/"* "$MISE_CACHE_PATH/installs/" 2>/dev/null || true
    echo "[RSOLV] Cached runtimes: $(ls "$MISE_CACHE_PATH/installs/" 2>/dev/null | tr '\n' ' ')"
  fi
}
trap persist_mise_cache EXIT
# --- End mise runtime cache ---

# Map GitHub Action inputs to expected environment variables
# GitHub Actions passes inputs as INPUT_<UPPERCASE_NAME>
if [ -n "$INPUT_RSOLVAPIKEY" ]; then
  export RSOLV_API_KEY="$INPUT_RSOLVAPIKEY"
  echo "Mapped INPUT_RSOLVAPIKEY to RSOLV_API_KEY"
fi

# Map github-token input to GITHUB_TOKEN
# GitHub Actions sets INPUT_GITHUB-TOKEN from the action input default (${{ github.token }})
# but the hyphenated name isn't valid as a shell variable, so we check the env directly.
if [ -z "$GITHUB_TOKEN" ]; then
  # Try the input variable (GitHub normalizes input names to INPUT_<UPPER>)
  GH_TOKEN_INPUT=$(printenv 'INPUT_GITHUB-TOKEN' 2>/dev/null || true)
  if [ -n "$GH_TOKEN_INPUT" ]; then
    export GITHUB_TOKEN="$GH_TOKEN_INPUT"
    echo "Mapped INPUT_GITHUB-TOKEN to GITHUB_TOKEN"
  fi
fi

# Rewrite SSH URLs to token-authenticated HTTPS globally in the container.
# This serves two purposes:
# 1. Prevents the AI from accidentally setting SSH push URLs during MITIGATE
# 2. Enables private git dependencies (Gemfile, package.json, requirements.txt)
#    that use git@github.com: URLs to authenticate via GITHUB_TOKEN
if [ -n "$GITHUB_TOKEN" ]; then
  git config --global url."https://x-access-token:${GITHUB_TOKEN}@github.com/".insteadOf "git@github.com:" 2>/dev/null || true
  git config --global url."https://x-access-token:${GITHUB_TOKEN}@github.com/".insteadOf "ssh://git@github.com/" 2>/dev/null || true
fi

# Run the action using the built output from /app
# NOTE: Do NOT use `exec` here — it replaces the shell process, which prevents
# the EXIT trap (persist_mise_cache) from firing. Without exec, the shell remains
# as parent, bun runs as child, and the trap fires after bun exits.
bun run /app/dist/index.js
