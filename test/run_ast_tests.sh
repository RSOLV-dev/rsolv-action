#!/bin/bash
# Script to run AST-related tests for RFC-031

echo "Running AST Multi-Language Parsing Tests..."
echo "=========================================="

cd "$(dirname "$0")/.."

# Run specific AST tests
mix test test/rsolv_api/ast/port_poc_test.exs --color
mix test test/rsolv_api/ast/multi_language_parsing_test.exs --color

# Run all AST tests
echo ""
echo "Running all AST tests..."
echo "========================"
mix test test/rsolv_api/ast/ --color

echo ""
echo "Test run complete!"