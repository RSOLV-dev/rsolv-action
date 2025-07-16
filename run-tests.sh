#!/bin/bash
# Test runner script that sets the DATABASE_URL for test environment

# Set the DATABASE_URL for test environment
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/rsolv_api_test"

# Run mix test with all arguments passed through
mix test "$@"