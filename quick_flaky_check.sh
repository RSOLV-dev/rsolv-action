#!/bin/bash

echo "Running tests 3 times to identify flaky tests..."
echo

# Run 1
echo "=== Run 1 (seed 100) ==="
mix test --exclude skip --exclude integration --seed 100 2>&1 | grep -E "^\s+[0-9]+\) test|failures" | tee run1.txt
echo

# Run 2  
echo "=== Run 2 (seed 200) ==="
mix test --exclude skip --exclude integration --seed 200 2>&1 | grep -E "^\s+[0-9]+\) test|failures" | tee run2.txt
echo

# Run 3
echo "=== Run 3 (seed 300) ==="
mix test --exclude skip --exclude integration --seed 300 2>&1 | grep -E "^\s+[0-9]+\) test|failures" | tee run3.txt
echo

echo "=== Summary ==="
echo "Run 1 failures:"
grep "failures" run1.txt
echo "Run 2 failures:"
grep "failures" run2.txt
echo "Run 3 failures:"
grep "failures" run3.txt

# Clean up
rm -f run1.txt run2.txt run3.txt