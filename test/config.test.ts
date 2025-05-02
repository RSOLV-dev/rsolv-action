import { describe, expect, test, mock, beforeEach, afterEach } from 'bun:test';
import { loadConfig } from '../src/config/index';
import * as fs from 'fs';
import * as path from 'path';

// Mock file system
mock('fs', () => {
  const actualFs = jest.requireActual('fs');
  const mockFiles: Record<string, string> = {};
  
  return {
    ...actualFs,
    existsSync: (filePath: string) => {
      if (filePath in mockFiles) {
        return true;
      }
      return actualFs.existsSync(filePath);
    },
    readFileSync: (filePath: string, options: any) => {
      if (filePath in mockFiles) {
        return mockFiles[filePath];
      }
      return actualFs.readFileSync(filePath, options);
    },
    writeFileSync: (filePath: string, data: string) => {
      mockFiles[filePath] = data;
    },
    _mockFiles: mockFiles,
    _clearMockFiles: () => {
      for (const key in mockFiles) {
        delete mockFiles[key];
      }
    }
  };
});

describe('Configuration Loading', () => {
  beforeEach(() => {
    // Reset environment variables before each test
    process.env = {
      ...process.env,
      RSOLV_API_KEY: 'env-api-key',
      RSOLV_CONFIG_PATH: '.github/rsolv.yml',
      RSOLV_ISSUE_LABEL: 'env-label',
      GITHUB_TOKEN: 'github-token',
      NODE_ENV: 'test'
    };
    
    // Clear mock files
    fs._clearMockFiles();
  });
  
  afterEach(() => {
    // Clear mock files
    fs._clearMockFiles();
  });
  
  test('loadConfig should load configuration from environment variables', async () => {
    const config = await loadConfig();
    
    expect(config).toBeDefined();
    expect(config.apiKey).toBe('env-api-key');
    expect(config.issueLabel).toBe('env-label');
    expect(config.repoToken).toBe('github-token');
  });
  
  test('loadConfig should load configuration from file', async () => {
    // Create mock config file
    fs.writeFileSync('.github/rsolv.yml', `
      apiKey: file-api-key
      issueLabel: file-label
      aiProvider:
        provider: openai
        model: gpt-4
        temperature: 0.3
    `);
    
    // Remove API key from environment to test file loading
    delete process.env.RSOLV_API_KEY;
    
    const config = await loadConfig();
    
    expect(config).toBeDefined();
    expect(config.apiKey).toBe('file-api-key');
    expect(config.issueLabel).toBe('file-label');
    expect(config.aiProvider.provider).toBe('openai');
    expect(config.aiProvider.model).toBe('gpt-4');
    expect(config.aiProvider.temperature).toBe(0.3);
  });
  
  test('loadConfig should merge configuration from multiple sources', async () => {
    // Create mock config file
    fs.writeFileSync('.github/rsolv.yml', `
      apiKey: file-api-key
      securitySettings:
        disableNetworkAccess: false
        scanDependencies: true
    `);
    
    const config = await loadConfig();
    
    expect(config).toBeDefined();
    // Environment variables take precedence over file
    expect(config.apiKey).toBe('env-api-key');
    expect(config.issueLabel).toBe('env-label');
    // File values should be merged
    expect(config.securitySettings.disableNetworkAccess).toBe(false);
    expect(config.securitySettings.scanDependencies).toBe(true);
  });
  
  test('loadConfig should use default values for missing properties', async () => {
    // Only provide API key, rest should use defaults
    process.env = {
      ...process.env,
      RSOLV_API_KEY: 'env-api-key',
      NODE_ENV: 'test'
    };
    
    const config = await loadConfig();
    
    expect(config).toBeDefined();
    expect(config.apiKey).toBe('env-api-key');
    expect(config.configPath).toBe('.github/rsolv.yml');
    expect(config.issueLabel).toBe('rsolv:automate');
    expect(config.aiProvider).toBeDefined();
    expect(config.containerConfig).toBeDefined();
    expect(config.securitySettings).toBeDefined();
  });
  
  test('loadConfig should validate configuration', async () => {
    // Remove required API key
    delete process.env.RSOLV_API_KEY;
    
    await expect(loadConfig()).rejects.toThrow('API key is required');
  });
  
  test('loadConfig should validate configuration schema', async () => {
    // Create invalid config file
    fs.writeFileSync('.github/rsolv.yml', `
      apiKey: test-api-key
      containerConfig:
        enabled: "not-a-boolean"
    `);
    
    await expect(loadConfig()).rejects.toThrow('Invalid configuration');
  });
});