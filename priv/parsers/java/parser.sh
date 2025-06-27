#!/bin/bash
# Fallback Java parser using JavaScript parser until proper Java environment is available

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JS_PARSER="$SCRIPT_DIR/../javascript/parser.js"

if [ -f "$JS_PARSER" ]; then
    # Use JavaScript parser as fallback for basic AST structure
    exec node "$JS_PARSER" "$@"
else
    echo '{"id":"unknown","status":"error","success":false,"error":{"type":"ParserNotAvailable","message":"Java parser requires JDK installation"}}' >&2
    exit 1
fi
