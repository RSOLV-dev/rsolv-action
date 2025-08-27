import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  test: {
    // Use jsdom for DOM/browser API mocking
    environment: 'node',
    
    // Global test timeout
    testTimeout: 10000,
    
    // Hook timeout
    hookTimeout: 10000,
    
    // Enable globals like describe, it, expect
    globals: true,
    
    // Setup files
    setupFiles: ['./test/vitest-setup.ts'],
    
    // Coverage settings
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/',
        'test/',
        '*.config.ts',
        '*.config.js',
      ]
    },
    
    // Mock config
    mockReset: true,
    clearMocks: true,
    restoreMocks: true,
    
    // Ignore patterns
    exclude: [
      '**/node_modules/**',
      '**/dist/**',
      '**/*.bun-backup',
      '**/vulnerable-apps/**',  // Exclude demo applications
    ],
    
    // Use vmThreads for better memory management
    pool: 'vmThreads',
    poolOptions: {
      vmThreads: {
        // Recycle workers more aggressively
        memoryLimit: '512MB',
        maxThreads: 2,
      }
    },
    
    // Log heap usage for debugging
    logHeapUsage: true,
    
    // Test sharding for large test suites
    maxConcurrency: 2,
    
    // Disable isolation for better performance (tests must be properly isolated)
    isolate: false,
    
    // Force garbage collection between tests
    teardownTimeout: 1000,
    
  },
  
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
});