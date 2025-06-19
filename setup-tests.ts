/**
 * Test setup file for Bun
 * This file runs before all tests to ensure clean test isolation
 */
import { mock, beforeEach, afterEach } from 'bun:test';

// Store original values
const originalFetch = global.fetch;
const originalNodeEnv = process.env.NODE_ENV;
const originalEnv = { ...process.env };

// Create a shared mock for fetch that can be reset between tests
let fetchMock: any;

// Global setup before all tests
function setupTestEnvironment() {
  // Set consistent test environment
  process.env.NODE_ENV = 'test';
  process.env.GITHUB_JOB = 'test_job';
  process.env.GITHUB_RUN_ID = 'test_run';
  process.env.RSOLV_API_URL = process.env.RSOLV_API_URL || 'https://api.rsolv.dev';
  
  // Don't mock fetch globally by default - let tests opt-in
  // Tests that need fetch mocked can use testUtils.mockFetch()
}

// Setup before each test file
beforeEach(() => {
  // Clear all mocks
  mock.restore();
  
  // Reset environment
  process.env = { ...originalEnv };
  setupTestEnvironment();
});

// Cleanup after each test file
afterEach(() => {
  // Restore original fetch if it was mocked
  if (global.fetch !== originalFetch) {
    global.fetch = originalFetch;
  }
  
  // Restore environment
  process.env = originalEnv;
  
  // Clear all mocks
  mock.restore();
  
  // Clean up module caches for better isolation
  for (const key in require.cache) {
    // Only delete our project modules, not node modules
    if (key.includes('/src/') || key.includes('/tests/')) {
      delete require.cache[key];
    }
  }
});

// Initial setup
setupTestEnvironment();

// Export utilities for tests
export const testUtils = {
  setupFetchMock: () => {
    // Create fetch mock if not already created
    if (!fetchMock) {
      fetchMock = mock((input: any, init?: any) => {
        console.warn(`[TEST] Unmocked fetch call to: ${input}`);
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({}),
          text: () => Promise.resolve(''),
          headers: new Headers(),
          redirected: false,
          statusText: 'OK',
          type: 'basic' as ResponseType,
          url: input?.toString() || '',
          clone: () => null,
          arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
          blob: () => Promise.resolve(new Blob()),
          formData: () => Promise.resolve(new FormData()),
          body: null,
          bodyUsed: false
        });
      });
      global.fetch = fetchMock as any;
    }
    return fetchMock;
  },
  
  mockFetch: (response: any) => {
    // Setup fetch mock if needed
    testUtils.setupFetchMock();
    
    const mockResponse = {
      ok: response.ok ?? true,
      status: response.status ?? 200,
      json: () => Promise.resolve(response.json || response.data || response),
      text: () => Promise.resolve(response.text || JSON.stringify(response.json || response.data || response)),
      headers: new Headers(response.headers || {}),
      redirected: false,
      statusText: response.statusText || 'OK',
      type: 'basic' as ResponseType,
      url: response.url || '',
      clone: function() { return this; },
      arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
      blob: () => Promise.resolve(new Blob()),
      formData: () => Promise.resolve(new FormData()),
      body: null,
      bodyUsed: false
    };
    
    fetchMock.mockResolvedValueOnce(mockResponse);
    return fetchMock;
  },
  
  mockFetchError: (error: Error) => {
    if (!fetchMock) {
      throw new Error('Fetch mock not initialized');
    }
    fetchMock.mockRejectedValueOnce(error);
    return fetchMock;
  },
  
  getFetchMock: () => fetchMock,
  
  resetMocks: () => {
    mock.restore();
    if (fetchMock) {
      fetchMock.mockClear();
    }
  }
};