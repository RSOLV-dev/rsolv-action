#!/bin/bash

echo "Checking parser files..."
echo

echo "Parser directories:"
ls -la priv/parsers/

echo
echo "JavaScript parser:"
ls -la priv/parsers/javascript/

echo
echo "Python parser:"
ls -la priv/parsers/python/

echo
echo "Ruby parser:"
ls -la priv/parsers/ruby/

echo
echo "PHP parser:"
ls -la priv/parsers/php/

echo
echo "Elixir parser:"
ls -la priv/parsers/elixir/

echo
echo "Checking if Elixir parser is executable:"
test -x priv/parsers/elixir/parser.exs && echo "✅ Executable" || echo "❌ Not executable"

echo
echo "Elixir parser config:"
cat priv/parsers/elixir/parser_config.json | jq .