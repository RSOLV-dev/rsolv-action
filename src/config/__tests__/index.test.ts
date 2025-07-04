import { describe, expect, test, beforeEach, afterEach, mock } from 'bun:test';
import { loadConfig } from '../index.js';
import fs from 'fs';
import * as yaml from 'js-yaml';

// Create mock functions
const mockExistsSync = mock((path: string) => path === '.github/rsolv.yml');
const mockReadFileSync = mock(() => '');

// Mock the modules
mock.module('fs', () => ({
  existsSync: mockExistsSync,
  readFileSync: mockReadFileSync,
}));

mock.module('../../utils/logger.js', () => ({
  logger: {
    info: mock(() => {}),
    debug: mock(() => {}),
    error: mock(() => {}),
    warn: mock(() => {}),
  }
}));

describe('Config Loading with maxIssues', () => {
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    // Save original environment
    originalEnv = { ...process.env };
    
    // Reset all environment variables
    delete process.env.RSOLV_API_KEY;
    delete process.env.RSOLV_MAX_ISSUES;
    delete process.env.RSOLV_CONFIG_PATH;
    
    // Set required API key
    process.env.RSOLV_API_KEY = 'test-api-key';
  });

  afterEach(() => {
    // Restore original environment
    process.env = originalEnv;
  });

  test('should load default config without maxIssues', async () => {
    const config = await loadConfig();
    
    expect(config.maxIssues).toBeUndefined();
    expect(config.apiKey).toBe('test-api-key');
  });

  test('should load maxIssues from environment variable', async () => {
    process.env.RSOLV_MAX_ISSUES = '5';
    
    const config = await loadConfig();
    
    expect(config.maxIssues).toBe(5);
  });

  test('should load maxIssues from config file', async () => {
    const mockConfig = {
      maxIssues: 3,
      aiProvider: {
        provider: 'claude-code',
        model: 'claude-3-sonnet-20240229'
      }
    };
    
    mockReadFileSync.mockReturnValueOnce(yaml.dump(mockConfig));
    
    const config = await loadConfig();
    
    expect(config.maxIssues).toBe(3);
  });

  test('environment variable should override config file for maxIssues', async () => {
    const mockConfig = {
      maxIssues: 3,
      aiProvider: {
        provider: 'claude-code',
        model: 'claude-3-sonnet-20240229'
      }
    };
    
    mockReadFileSync.mockReturnValueOnce(yaml.dump(mockConfig));
    process.env.RSOLV_MAX_ISSUES = '1';
    
    const config = await loadConfig();
    
    expect(config.maxIssues).toBe(1);
  });

  test('should handle invalid maxIssues values', async () => {
    process.env.RSOLV_MAX_ISSUES = 'invalid';
    
    const config = await loadConfig();
    
    // Should be undefined because parseInt('invalid') returns NaN which is filtered out
    expect(config.maxIssues).toBeUndefined();
  });

  test('should handle zero maxIssues', async () => {
    process.env.RSOLV_MAX_ISSUES = '0';
    
    await expect(loadConfig()).rejects.toThrow();
  });

  test('should handle negative maxIssues', async () => {
    process.env.RSOLV_MAX_ISSUES = '-1';
    
    await expect(loadConfig()).rejects.toThrow();
  });
});