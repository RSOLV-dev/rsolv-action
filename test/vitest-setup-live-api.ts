// Setup for live API tests - NO MSW mocking
import { beforeAll, afterAll } from 'vitest';

// Prevent accidental Claude Code CLI execution in tests
process.env.RSOLV_USE_CLI = 'false';
process.env.FORCE_MOCK_CLAUDE_CODE = 'true';

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.CI = 'true';
process.env.LOG_LEVEL = 'error';
delete process.env.CLAUDE_CODE_PATH;

// Use real fetch for live API tests
// No MSW setup here - we want real HTTP requests

console.log('[Vitest Setup] Live API test environment configured (no MSW)');