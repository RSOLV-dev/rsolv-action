// Test preload file for Bun tests
// Sets up test environment

// Ensure NODE_ENV is set to test
process.env.NODE_ENV = 'test';

// Disable actual API calls during tests
process.env.DISABLE_API_CALLS = 'true';