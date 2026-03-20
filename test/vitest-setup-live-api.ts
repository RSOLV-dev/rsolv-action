// Setup for live API tests - NO MSW mocking

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.CI = 'true';
process.env.LOG_LEVEL = 'error';
delete process.env.CLAUDE_CODE_PATH;

// Use real fetch for live API tests
// No MSW setup here - we want real HTTP requests

console.log('[Vitest Setup] Live API test environment configured (no MSW)');
