/**
 * E2E Test Preload - Minimal utilities for end-to-end testing
 * 
 * This preload file provides minimal test utilities without global mocks
 * to enable real integration testing with actual services and APIs.
 */

// E2E Test Environment Detection
(globalThis as any).__E2E_MODE__ = true;

// Simple logger for E2E tests - no mocking, just console output
const createE2ELogger = () => ({
  info: (...args: any[]) => console.log('[E2E INFO]', ...args),
  warn: (...args: any[]) => console.warn('[E2E WARN]', ...args),
  error: (...args: any[]) => console.error('[E2E ERROR]', ...args),
  debug: (...args: any[]) => console.debug('[E2E DEBUG]', ...args),
  log: (...args: any[]) => console.log('[E2E LOG]', ...args)
});

// E2E Test Utilities (minimal set, no global mocks)
(globalThis as any).__E2E_TEST_UTILS__ = {
  // Simple test environment detection
  isE2EMode: () => true,
  
  // Environment helpers
  getApiUrl: () => process.env.RSOLV_API_URL || 'https://api.rsolv-staging.com',
  getApiKey: () => process.env.RSOLV_API_KEY,
  getGitHubToken: () => process.env.GITHUB_TOKEN,
  
  // Real logger (no mocking)
  createLogger: createE2ELogger,
  
  // Basic cleanup utilities
  cleanupTestArtifacts: async () => {
    // Clean up any test-specific artifacts
    // This is minimal cleanup that doesn't interfere with real operations
  },
  
  // Simple wait utility for E2E tests
  wait: (ms: number) => new Promise(resolve => setTimeout(resolve, ms)),
  
  // Environment validation
  validateE2EEnvironment: () => {
    const required = ['RSOLV_API_KEY', 'GITHUB_TOKEN'];
    const missing = required.filter(key => !process.env[key]);
    
    if (missing.length > 0) {
      throw new Error(`Missing required E2E environment variables: ${missing.join(', ')}`);
    }
    
    return {
      apiUrl: process.env.RSOLV_API_URL || 'https://api.rsolv-staging.com',
      apiKey: process.env.RSOLV_API_KEY,
      githubToken: process.env.GITHUB_TOKEN,
      environment: process.env.E2E_ENVIRONMENT || 'staging'
    };
  },
  
  // HTTP client for real API calls (no mocking)
  createHttpClient: (baseUrl?: string) => {
    const url = baseUrl || process.env.RSOLV_API_URL || 'https://api.rsolv-staging.com';
    
    return {
      get: async (path: string, headers: Record<string, string> = {}) => {
        const response = await fetch(`${url}${path}`, {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json',
            ...headers
          }
        });
        
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        return response.json();
      },
      
      post: async (path: string, data: any, headers: Record<string, string> = {}) => {
        const response = await fetch(`${url}${path}`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...headers
          },
          body: JSON.stringify(data)
        });
        
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        return response.json();
      }
    };
  }
};

// Set E2E-specific environment variables
process.env.NODE_ENV = process.env.NODE_ENV || 'test';
process.env.E2E_MODE = 'true';

// Log E2E mode initialization
console.log('[E2E] E2E test environment initialized');
console.log('[E2E] API URL:', process.env.RSOLV_API_URL || 'https://api.rsolv-staging.com');
console.log('[E2E] Environment:', process.env.E2E_ENVIRONMENT || 'staging');