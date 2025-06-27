#!/bin/bash
# PHP AST Parser wrapper script for RSOLV RFC-031

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PHP_FILE="$SCRIPT_DIR/parser.php"

# Check if composer dependencies are installed
if [ ! -d "$SCRIPT_DIR/vendor" ]; then
    echo "Error: Composer dependencies not installed" >&2
    echo "Please run 'composer install' in the php parser directory first" >&2
    exit 1
fi

# Check if PHP is available
if ! command -v php >/dev/null 2>&1; then
    echo "Error: PHP not found in PATH" >&2
    exit 1
fi

# Run the PHP parser
exec php "$PHP_FILE" "$@"