// Test preload file to handle module mocking before any imports
// This runs before any test files to ensure clean module loading
import { mock } from 'bun:test';

// Mock logger module globally before any imports
mock.module('./src/utils/logger.js', () => ({
  logger: {
    info: mock(() => {}),
    warn: mock(() => {}),
    error: mock(() => {}),
    debug: mock(() => {})
  }
}));

// Mock fetch globally but make it opt-in per test
// This prevents the global fetch mock from interfering with E2E tests
const originalFetch = globalThis.fetch;

// Create a global test utilities object
(globalThis as any).__RSOLV_TEST_UTILS__ = {
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
  
  // Reset all mocks
  resetAllMocks: () => {
    mock.restore();
  }
};