/**
 * Bun Test Preload Configuration
 * 
 * This file is loaded before all tests run to set up the test environment
 * and prevent test pollution between test suites.
 */

// @ts-ignore - Bun test types
import { afterEach, beforeEach, mock } from 'bun:test';

// Global test setup
beforeEach(() => {
  // Reset any global state if needed
});

// Global test cleanup to prevent pollution
afterEach(() => {
  // Clear all mocks after each test
  // Note: As of Bun 1.2.15, clearAllMocks is not yet available
  // See: https://github.com/oven-sh/bun/issues/9079
  // Individual mocks need to be cleared manually in each test
  
  // Note: mock.module() mocks persist across test files
  // See: https://github.com/oven-sh/bun/issues/6040
  // Workaround: Use require.resolve() instead of string literals
});

// Export empty object to make this a module
export {};