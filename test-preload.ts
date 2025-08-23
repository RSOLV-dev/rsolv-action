// Test preload for bun test
// Sets up test environment

// Mock fetch globally if needed
if (!global.fetch) {
  global.fetch = (async () => {
    throw new Error('fetch not mocked in this test');
  }) as any; // Type assertion needed for test mock
}

// Set test environment
process.env.NODE_ENV = 'test';