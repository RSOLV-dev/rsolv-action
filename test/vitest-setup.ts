// Global setup for Vitest tests
import { afterEach, vi } from 'vitest';

// Mock fetch globally
global.fetch = vi.fn(() =>
  Promise.resolve({
    ok: true,
    status: 200,
    json: () => Promise.resolve({}),
    text: () => Promise.resolve(''),
  } as Response)
);

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.CI = 'true';
process.env.LOG_LEVEL = 'error';

// Global cleanup after each test
afterEach(() => {
  // Clear all mocks
  vi.clearAllMocks();
  
  // Clear all timers
  vi.clearAllTimers();
  
  // Reset fetch mock
  if (global.fetch && typeof (global.fetch as any).mockReset === 'function') {
    (global.fetch as any).mockReset();
  }
});

// Mock commonly problematic modules globally
vi.mock('child_process', () => ({
  execSync: vi.fn(() => ''),
  exec: vi.fn(),
  spawn: vi.fn(() => ({
    on: vi.fn(),
    stdout: { on: vi.fn() },
    stderr: { on: vi.fn() },
    kill: vi.fn(),
  })),
}));

// Mock fs for tests that don't need real file system
vi.mock('fs', () => ({
  existsSync: vi.fn(() => true),
  readFileSync: vi.fn(() => ''),
  writeFileSync: vi.fn(),
  mkdirSync: vi.fn(),
  promises: {
    readFile: vi.fn(() => Promise.resolve('')),
    writeFile: vi.fn(() => Promise.resolve()),
    mkdir: vi.fn(() => Promise.resolve()),
    rm: vi.fn(() => Promise.resolve()),
  },
}));

// Mock the Claude Code SDK
vi.mock('@anthropic-ai/claude-code', () => ({
  ClaudeCodeSDK: vi.fn().mockImplementation(() => ({
    query: vi.fn(() => Promise.resolve({ success: true })),
    close: vi.fn(),
  })),
}));

console.log('[Vitest Setup] Test environment configured');