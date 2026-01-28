/**
 * MSW Server Setup for Tests
 * Provides network-level API mocking for all HTTP requests
 */

import { afterEach } from 'vitest';
import { setupServer } from 'msw/node';
import { handlers } from './handlers.js';

// Create the server instance with default handlers
export const server = setupServer(...handlers);

// Track if MSW server is started to avoid double-patching
let serverStarted = false;

/**
 * Start MSW server once at module load time.
 * This avoids the "already patched" error that occurs when server.listen()
 * is called multiple times in beforeAll hooks.
 */
function startServerOnce() {
  if (serverStarted) {
    return;
  }
  serverStarted = true;
  server.listen({
    onUnhandledRequest: 'warn' // Warn about unhandled requests in tests
  });
}

// Start server at module load (not in hooks)
startServerOnce();

// Setup function for vitest-setup.ts - just registers cleanup hooks
export function setupMSW() {
  // Reset handlers after each test
  afterEach(() => {
    server.resetHandlers();
  });

  // Note: We don't register beforeAll/afterAll here anymore
  // The server is started at module load time and stays running
  // This prevents "already patched" errors when running in shards
}

// Export for manual control in tests
export { HttpResponse } from 'msw';