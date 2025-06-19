/**
 * Test setup file for Bun - Legacy approach, now using test-preload.ts
 * This provides utilities for tests but module mocking is done in preload
 */
import { mock, beforeEach, afterEach } from 'bun:test';

// Access the global test utilities from preload
const globalTestUtils = (globalThis as any).__RSOLV_TEST_UTILS__;

// Store original values
const originalNodeEnv = process.env.NODE_ENV;
const originalEnv = { ...process.env };

// Global setup before all tests
function setupTestEnvironment() {
  // Set consistent test environment
  process.env.NODE_ENV = 'test';
  process.env.GITHUB_JOB = 'test_job';
  process.env.GITHUB_RUN_ID = 'test_run';
  process.env.RSOLV_API_URL = process.env.RSOLV_API_URL || 'https://api.rsolv.dev';
}

// Setup before each test file
beforeEach(() => {
  // Reset environment
  process.env = { ...originalEnv };
  setupTestEnvironment();
  
  // Reset fetch to original state
  if (globalTestUtils) {
    globalTestUtils.restoreFetch();
  }
});

// Cleanup after each test file
afterEach(() => {
  // Restore environment
  process.env = originalEnv;
  
  // Reset all test utilities
  if (globalTestUtils) {
    globalTestUtils.resetAllMocks();
    globalTestUtils.restoreFetch();
  }
});

// Initial setup
setupTestEnvironment();

// Export utilities for tests - delegate to global test utils
export const testUtils = globalTestUtils || {
  setupFetchMock: () => console.warn('Test utils not loaded from preload'),
  mockFetch: () => console.warn('Test utils not loaded from preload'),
  mockFetchError: () => console.warn('Test utils not loaded from preload'),
  resetMocks: () => console.warn('Test utils not loaded from preload'),
  restoreFetch: () => console.warn('Test utils not loaded from preload')
};