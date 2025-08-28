#!/bin/bash

echo "Analyzing test suite failures by module and category..."
echo "========================================================"
echo ""

# Temporary file for results
RESULTS_FILE=".all-test-results.json"

# Run all tests with JSON reporter (memory limited)
echo "Running full test suite with JSON reporter..."
NODE_OPTIONS="--max-old-space-size=4096" \
NODE_ENV=test \
USE_LOCAL_PATTERNS=true \
npx vitest run --reporter=json --no-coverage 2>/dev/null > $RESULTS_FILE

# Check if we got valid JSON
if [ ! -s $RESULTS_FILE ]; then
  echo "Failed to generate test results"
  exit 1
fi

# Overall statistics
echo "Overall Statistics:"
echo "-------------------"
jq -r '. | "Total Tests: \(.numTotalTests)\nPassed: \(.numPassedTests)\nFailed: \(.numFailedTests)\nPass Rate: \(((.numPassedTests/.numTotalTests)*100 | floor*10 | ./10))%"' $RESULTS_FILE

echo ""
echo "Failures by Module:"
echo "-------------------"

# Extract failed tests and categorize them
jq -r '.testResults[] | select(.status == "failed" or (.assertionResults | map(select(.status == "failed")) | length) > 0) | .name' $RESULTS_FILE | while read -r file; do
  # Extract module from path
  MODULE=$(echo "$file" | sed 's|.*/RSOLV-action/src/||' | cut -d'/' -f1-2)
  echo "$MODULE"
done | sort | uniq -c | sort -rn

echo ""
echo "Failed Test Details:"
echo "--------------------"

# Get detailed failure information
jq -r '.testResults[] | 
  . as $suite | 
  .assertionResults[] | 
  select(.status == "failed") | 
  "\($suite.name | sub(".*/RSOLV-action/src/"; "src/") | sub("/[^/]+$"; "")) - \(.title)"' $RESULTS_FILE | sort

# Cleanup
rm -f $RESULTS_FILE
