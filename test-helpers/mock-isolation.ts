/**
 * Test helper for proper mock isolation in Bun tests
 * Prevents mock pollution between test files
 */

import { mock } from 'bun:test';

interface MockStore {
  originalFetch?: typeof fetch;
  originalConsoleLog?: typeof console.log;
  originalConsoleError?: typeof console.error;
  originalConsoleWarn?: typeof console.warn;
  originalEnv?: NodeJS.ProcessEnv;
}

const mockStore: MockStore = {};

/**
 * Save original global values before mocking
 */
export function saveMockContext() {
  mockStore.originalFetch = global.fetch;
  mockStore.originalConsoleLog = console.log;
  mockStore.originalConsoleError = console.error;
  mockStore.originalConsoleWarn = console.warn;
  mockStore.originalEnv = { ...process.env };
}

/**
 * Restore original global values after tests
 */
export function restoreMockContext() {
  if (mockStore.originalFetch) {
    global.fetch = mockStore.originalFetch;
  }
  if (mockStore.originalConsoleLog) {
    console.log = mockStore.originalConsoleLog;
  }
  if (mockStore.originalConsoleError) {
    console.error = mockStore.originalConsoleError;
  }
  if (mockStore.originalConsoleWarn) {
    console.warn = mockStore.originalConsoleWarn;
  }
  if (mockStore.originalEnv) {
    process.env = mockStore.originalEnv;
  }
  
  // Clear all Bun mocks
  mock.restore();
}

/**
 * Create an isolated mock for fetch that won't pollute other tests
 */
export function createIsolatedFetchMock() {
  const fetchMock = mock(() => Promise.resolve());
  
  // Store original if not already stored
  if (!mockStore.originalFetch) {
    mockStore.originalFetch = global.fetch;
  }
  
  global.fetch = fetchMock as any;
  return fetchMock;
}

/**
 * Create a properly typed mock response
 */
export function createMockResponse(data: any, options: { ok?: boolean; status?: number } = {}) {
  return {
    ok: options.ok ?? true,
    status: options.status ?? 200,
    json: mock(() => Promise.resolve(data)),
    text: mock(() => Promise.resolve(JSON.stringify(data))),
    headers: new Headers(),
    redirected: false,
    statusText: 'OK',
    type: 'basic' as ResponseType,
    url: '',
    clone: mock(() => createMockResponse(data, options)),
    arrayBuffer: mock(() => Promise.resolve(new ArrayBuffer(0))),
    blob: mock(() => Promise.resolve(new Blob())),
    formData: mock(() => Promise.resolve(new FormData())),
    body: null,
    bodyUsed: false
  };
}

/**
 * Setup mock isolation for a test suite
 * Call this in beforeAll/beforeEach
 */
export function setupMockIsolation() {
  saveMockContext();
  
  // Ensure clean mock state
  mock.restore();
  
  // Reset environment to known state
  process.env = {
    ...mockStore.originalEnv,
    NODE_ENV: 'test',
    GITHUB_JOB: 'test_job',
    GITHUB_RUN_ID: 'test_run'
  };
}

/**
 * Cleanup mock isolation after tests
 * Call this in afterAll/afterEach
 */
export function cleanupMockIsolation() {
  restoreMockContext();
}