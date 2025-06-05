/**
 * Global test setup for Bun tests
 * This file is loaded before all tests to ensure consistent environment
 */

import { mock } from 'bun:test';

// Save original global values
const originalFetch = global.fetch;
const originalEnv = { ...process.env };

// Set up test environment
process.env.NODE_ENV = 'test';
process.env.GITHUB_JOB = 'test_job';
process.env.GITHUB_RUN_ID = 'test_run';
process.env.RSOLV_API_URL = 'https://api.rsolv.dev';

// Create a controlled fetch mock
const fetchMock = mock(() => Promise.resolve({
  ok: true,
  status: 200,
  json: mock(() => Promise.resolve({})),
  text: mock(() => Promise.resolve('')),
  headers: new Headers(),
  redirected: false,
  statusText: 'OK',
  type: 'basic' as ResponseType,
  url: '',
  clone: mock(() => null),
  arrayBuffer: mock(() => Promise.resolve(new ArrayBuffer(0))),
  blob: mock(() => Promise.resolve(new Blob())),
  formData: mock(() => Promise.resolve(new FormData())),
  body: null,
  bodyUsed: false
}));

// Replace global fetch with mock
global.fetch = fetchMock as any;

// Export for tests to use
export { fetchMock, originalFetch, originalEnv };

// Clean up after all tests
if (typeof afterAll !== 'undefined') {
  afterAll(() => {
    global.fetch = originalFetch;
    process.env = originalEnv;
    mock.restore();
  });
}