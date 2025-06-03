#!/bin/sh
set -e

# The idiomatic approach: Run migrations in a separate step before deployment
# This script just starts the app

exec bin/rsolv_api start