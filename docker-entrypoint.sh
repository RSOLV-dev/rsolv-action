#!/bin/sh
# Docker entrypoint script for RSOLV API
# Ensures pattern beam files are available even with volume mounts

set -e

# If we're in development and _build is not available (volume mount scenario)
if [ ! -d "/app/_build" ] || [ -z "$(ls -A /app/_build 2>/dev/null)" ]; then
    echo "Detected volume mount scenario - setting up build directory..."
    
    # Run initial compilation to create _build structure
    cd /app
    mix deps.get
    mix deps.compile
    mix compile
    
    echo "Build directory created and application compiled."
fi

# Execute the original command
exec "$@"