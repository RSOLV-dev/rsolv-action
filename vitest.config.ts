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
    ],
    
    // Run tests sequentially by default to avoid conflicts
    // Can be overridden with --parallel flag
    pool: 'forks',
    poolOptions: {
      forks: {
        singleFork: true,
      }
    },
    
  },
  
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
});