// Test preload file to handle module mocking before any imports
// This runs before any test files to ensure clean module loading
// Based on Bun test pollution research: https://github.com/oven-sh/bun/issues/6040
import { mock } from 'bun:test';
import { performCompleteCleanup, performSyncCleanup, waitForPendingTasks } from './test-sync-utils.js';

// Store original globals and module states
const originalFetch = globalThis.fetch;
const originalEnv = { ...process.env };
const originalConsole = { ...console };
const originalRequire = require;
const originalGlobalThis = { ...globalThis };

// Enhanced isolation based on research findings
function createIsolatedEnvironment() {
  // Reset environment to clean state
  process.env = { 
    ...originalEnv,
    NODE_ENV: 'test',
    GITHUB_JOB: 'test_job',
    GITHUB_RUN_ID: 'test_run'
  };
  
  // Clear any test-specific environment variables that might interfere
  delete process.env.RSOLV_API_KEY;
  delete process.env.RSOLV_CONFIG_PATH;
  delete process.env.RSOLV_ISSUE_LABEL;
  delete process.env.RSOLV_API_URL;
  delete process.env.RSOLV_USE_LOCAL_PATTERNS;
  
  // Reset fetch and other globals
  globalThis.fetch = originalFetch;
  
  // Clear any test-specific globals that might leak
  delete (globalThis as any).__RSOLV_TEST_STATE__;
  delete (globalThis as any).__RSOLV_MOCK_RESPONSES__;
}

// Create a global test utilities object with enhanced isolation
// Address module cache and global state pollution per research
(globalThis as any).__RSOLV_TEST_UTILS__ = {
  // Create a consistent logger mock structure
  createLoggerMock: () => ({
    logger: {
      info: mock(() => {}),
      warn: mock(() => {}),
      error: mock(() => {}),
      debug: mock(() => {}),
      log: mock(() => {})
    }
  }),
  
  setupFetchMock: (mockResponse?: any) => {
    const mockFetch = mock((url: string, options?: RequestInit) => {
      if (mockResponse) {
        return Promise.resolve(mockResponse);
      }
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ patterns: [] }),
        text: () => Promise.resolve('')
      });
    });
    globalThis.fetch = mockFetch;
    return mockFetch;
  },
  
  restoreFetch: () => {
    globalThis.fetch = originalFetch;
  },
  
  // Enhanced reset for better isolation based on Bun research
  resetAllMocks: async () => {
    try {
      // Reset all function mocks
      mock.restore();
      
      // Clear module cache pollution (based on Bun issue #6040)
      if (require.cache) {
        Object.keys(require.cache).forEach(key => {
          if (key.includes('test') || key.includes('mock') || key.includes('__tests__')) {
            delete require.cache[key];
          }
        });
      }
      
      createIsolatedEnvironment();
      
      // Use proper async cleanup instead of sleep
      await waitForPendingTasks();
    } catch (error) {
      console.warn('Mock reset failed:', error);
    }
  },
  
  // Synchronous version for cases where async isn't possible
  resetAllMocksSync: () => {
    try {
      mock.restore();
      createIsolatedEnvironment();
      performSyncCleanup();
    } catch (error) {
      console.warn('Sync mock reset failed:', error);
    }
  },
  
  // Completely reset environment between test files
  resetEnvironment: () => {
    createIsolatedEnvironment();
  },
  
  // Force cleanup of any leaked state using proper async patterns
  forceCleanup: async () => {
    await performCompleteCleanup();
    createIsolatedEnvironment();
  },
  
  // Synchronous force cleanup
  forceCleanupSync: () => {
    performSyncCleanup();
    createIsolatedEnvironment();
  }
};

// Initialize clean environment
createIsolatedEnvironment();