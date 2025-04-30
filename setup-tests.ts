/**
 * Test setup file for Bun
 * This file runs before each test file to ensure clean test isolation
 */

// Store original Node environment
const originalNodeEnv = process.env.NODE_ENV;

// Reset environment before each test file
beforeEach(() => {
  // Set test environment
  process.env.NODE_ENV = 'test';
});

// Clean up after each test file
afterEach(() => {
  // Restore original environment
  process.env.NODE_ENV = originalNodeEnv;

  // Clean up module caches that might be affecting test isolation
  // This helps ensure each test file gets a fresh state
  for (const key in require.cache) {
    // Only delete our project modules, not node modules
    if (key.includes('/src/')) {
      delete require.cache[key];
    }
  }
});