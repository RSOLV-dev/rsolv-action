#!/bin/bash
# Go AST Parser wrapper script for RSOLV RFC-031

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_FILE="$SCRIPT_DIR/parser"

# Check if Go is available
if ! command -v go >/dev/null 2>&1; then
    echo "Error: Go not found in PATH" >&2
    exit 1
fi

# Build the parser if binary doesn't exist or source is newer
if [ ! -f "$BINARY_FILE" ] || [ "$SCRIPT_DIR/parser.go" -nt "$BINARY_FILE" ]; then
    echo "Building Go parser..." >&2
    cd "$SCRIPT_DIR"
    if ! go build -o parser parser.go; then
        echo "Error: Failed to build Go parser" >&2
        exit 1
    fi
fi

# Run the Go parser
exec "$BINARY_FILE" "$@"