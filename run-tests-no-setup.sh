#!/bin/bash
# Run tests without the global setup-tests.ts preload

# Temporarily rename setup-tests.ts to disable it
mv setup-tests.ts setup-tests.ts.bak 2>/dev/null || true

# Run tests
echo "Running tests without global setup..."
bun test "$@"
TEST_RESULT=$?

# Restore setup-tests.ts
mv setup-tests.ts.bak setup-tests.ts 2>/dev/null || true

exit $TEST_RESULT