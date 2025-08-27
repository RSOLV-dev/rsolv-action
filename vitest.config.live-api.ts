import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  test: {
    // Use node environment
    environment: 'node',
    
    // Global test timeout
    testTimeout: 30000, // Longer timeout for live API calls
    
    // Hook timeout
    hookTimeout: 10000,
    
    // Enable globals like describe, it, expect
    globals: true,
    
    // Setup files - different setup for live API tests
    setupFiles: ['./test/vitest-setup-live-api.ts'],
    
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
    
    // Include only live API tests
    include: [
      '**/ast-validator-live-api.test.ts',
      '**/ast-validator-e2e.test.ts',
      '**/*-live-api.test.ts',
      '**/*-e2e.test.ts'
    ],
    
    // Ignore patterns
    exclude: [
      '**/node_modules/**',
      '**/dist/**',
      '**/*.bun-backup',
      '**/vulnerable-apps/**',
    ],
    
    // Use vmThreads for better memory management
    pool: 'vmThreads',
    poolOptions: {
      vmThreads: {
        memoryLimit: '512MB',
        maxThreads: 2,
      }
    },
    
    // Log heap usage for debugging
    logHeapUsage: true,
    
    // Test sharding for large test suites
    maxConcurrency: 1, // Run one at a time for API tests
    
    // Force garbage collection between tests
    teardownTimeout: 1000,
  },
  
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
});