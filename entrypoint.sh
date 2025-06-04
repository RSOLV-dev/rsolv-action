#!/bin/sh
set -e

# Change to app directory where our code is
cd /app

# Run the action using the built output
bun run dist/index.js
