#!/bin/bash
# Setup environment for RSOLV demo
# Source this file before running demo scripts

# Load environment variables from .envrc
if [ -f "/home/dylan/dev/rsolv/.envrc" ]; then
    source /home/dylan/dev/rsolv/.envrc
fi

# Use internal API key if RSOLV_API_KEY not set
if [ -z "$RSOLV_API_KEY" ]; then
    if [ -n "$RSOLV_INTERNAL_API_KEY" ]; then
        export RSOLV_API_KEY="$RSOLV_INTERNAL_API_KEY"
        echo "✓ RSOLV_API_KEY configured from internal key"
    else
        echo "✗ Warning: No RSOLV API key available"
        echo "  The demo repository has RSOLV_API_KEY as a GitHub secret"
        echo "  For local testing, set RSOLV_INTERNAL_API_KEY in .envrc"
        return 1
    fi
else
    echo "✓ RSOLV_API_KEY already configured"
fi

# Set API URL if not set
if [ -z "$RSOLV_API_URL" ]; then
    export RSOLV_API_URL="https://api.rsolv.ai"
    echo "✓ RSOLV_API_URL set to: $RSOLV_API_URL"
else
    echo "✓ RSOLV_API_URL already set to: $RSOLV_API_URL"
fi

# Verify GitHub authentication
if gh auth status > /dev/null 2>&1; then
    echo "✓ GitHub CLI authenticated"
else
    echo "✗ GitHub CLI not authenticated. Run: gh auth login"
    return 1
fi

echo ""
echo "Environment ready for RSOLV demo!"
echo "You can now run:"
echo "  ./demo-scripts/demo-pre-flight-check.sh"
echo "  ./demo-scripts/demo-rehearsal.sh"
echo "  ./demo-scripts/demo-master.sh"