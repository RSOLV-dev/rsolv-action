// Set test environment variables - MUST be set before any imports
process.env.NODE_ENV = 'test';
process.env.CI = 'true';
process.env.LOG_LEVEL = 'error';
process.env.RSOLV_API_KEY = 'staging-master-key-123';
process.env.RSOLV_API_URL = 'https://api.rsolv-staging.com';
// Ensure no executable path is set in tests (allows NODE_ENV=test check to work)
delete process.env.CLAUDE_CODE_PATH;

// Note: localStorage/sessionStorage polyfills are in vitest-polyfills.ts
// which MUST be loaded before this file (see vitest.config.ts setupFiles order)

// Global setup for Vitest tests
import { afterEach, vi, beforeAll, afterAll } from 'vitest';
import { setupMSW } from '../src/test/mocks/server';

// Setup MSW for API mocking
setupMSW();

// Prevent accidental Claude Code CLI execution in tests
process.env.RSOLV_USE_CLI = 'false';
process.env.FORCE_MOCK_CLAUDE_CODE = 'true';

// DO NOT mock fetch globally - let MSW handle it
// Only mock fetch in specific tests that need it

// Global cleanup after each test
afterEach(() => {
  // Clear all mocks
  vi.clearAllMocks();

  // Clear all timers
  vi.clearAllTimers();

  // Reset modules to prevent mock contamination between tests
  vi.resetModules();

  // Force garbage collection if available (requires --expose-gc flag)
  if (global.gc) {
    global.gc();
  }
});

// DO NOT mock modules globally - let individual tests mock what they need
// This prevents mock conflicts between test files
// Only exception: MSW for HTTP requests (handled above)

// Don't mock fs globally - let individual tests mock as needed
// This prevents issues with modules that legitimately need fs access

// Individual tests should mock their own dependencies as needed

console.log('[Vitest Setup] Test environment configured');