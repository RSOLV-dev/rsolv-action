#!/bin/bash

# Run tests in shards to manage memory usage
# Usage: ./run-tests-sharded.sh [num_shards]

NUM_SHARDS=${1:-4}  # Default to 4 shards

echo "Running tests in $NUM_SHARDS shards..."

# Create reports directory
mkdir -p .vitest-reports

# Run each shard
for i in $(seq 1 $NUM_SHARDS); do
  echo "Running shard $i/$NUM_SHARDS..."
  RSOLV_API_KEY=${RSOLV_API_KEY:-rsolv_staging_api_key_19278} \
  RSOLV_API_URL=${RSOLV_API_URL:-https://api-staging.rsolv.dev} \
  npx vitest run --reporter=blob --shard=$i/$NUM_SHARDS || exit 1
done

# Merge results
echo "Merging test results..."
npx vitest --merge-reports

echo "Tests completed!"