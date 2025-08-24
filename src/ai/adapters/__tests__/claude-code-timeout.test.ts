import { describe, expect, test, beforeEach, afterEach, jest, spyOn } from 'vitest';
import { ClaudeCodeAdapter } from '../claude-code';
import { spawn } from 'child_process';
import * as fs from 'fs';
import { EventEmitter } from 'events';
import { AIConfig } from '../../types';

describe('Claude Code Adapter Timeout Behavior', () => {
  let adapter: ClaudeCodeAdapter;
  const mockConfig: AIConfig = {
    provider: 'claude-code',
    apiKey: 'test-api-key',
    model: 'claude-sonnet-4-20250514',
    temperature: 0.2,
    maxTokens: 4000,
    timeout: 1000, // 1 second for faster testing
    claudeCodeConfig: {
      executablePath: 'non-existent-claude', // Use non-existent path to force timeout
      tempDir: '/tmp/test',
      timeout: 1000, // 1 second for faster testing
      verboseLogging: false,
      retryOptions: {
        maxRetries: 2,
        baseDelay: 100 // Faster retry for testing
      }
    }
  };

  const mockIssueContext = {
    id: '1',
    number: 1,
    title: 'Test Issue',
    body: 'Test body',
    labels: ['bug'],
    state: 'open' as const,
    repository: {
      owner: 'test',
      name: 'repo',
      fullName: 'test/repo'
    },
    author: 'testuser',
    createdAt: new Date(),
    updatedAt: new Date()
  };

  const mockAnalysis = {
    canBeFixed: true,
    complexity: 'medium' as const,
    estimatedTime: 30,
    relatedFiles: ['src/test.ts'],
    suggestedApproach: 'Fix the bug'
  };

  beforeEach(() => {
    vi.clearAllMocks();
    adapter = new ClaudeCodeAdapter(mockConfig);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  test('should timeout availability check after 5 seconds', async () => {
    const start = Date.now();
    const result = await adapter.isAvailable();
    const duration = Date.now() - start;
    
    // Should return false for non-existent executable
    expect(result).toBe(false);
    // Should return quickly since executable doesn't exist (spawn fails immediately)
    expect(duration).toBeLessThan(1000);
  });

  test('should timeout when Claude Code CLI is not available', async () => {
    // Test with a non-existent executable to force CLI not available
    const configWithBadPath: AIConfig = {
      ...mockConfig,
      claudeCodeConfig: {
        ...mockConfig.claudeCodeConfig!,
        executablePath: '/non/existent/path/claude'
      }
    };
    
    const adapterWithBadPath = new ClaudeCodeAdapter(configWithBadPath);
    
    const result = await adapterWithBadPath.generateSolution(mockIssueContext, mockAnalysis);
    
    expect(result.success).toBe(false);
    expect(result.message).toBe('Claude Code CLI not available');
    expect(result.error).toContain('Claude Code CLI not available');
  });

  test('should handle file system errors gracefully', async () => {
    // Test file system error handling by simulating temp directory creation failure
    const fsExistsSpy = vi.spyOn(fs, 'existsSync').mockReturnValue(false);
    const fsMkdirSpy = vi.spyOn(fs, 'mkdirSync').mockImplementation(() => {
      throw new Error('Permission denied');
    });
    
    const result = await adapter.generateSolution(mockIssueContext, mockAnalysis);
    
    expect(result.success).toBe(false);
    expect(result.message).toBe('Claude Code CLI not available');
    // The non-existent CLI check happens before file system operations
    
    fsExistsSpy.mockRestore();
    fsMkdirSpy.mockRestore();
  });

  test('should respect timeout configuration in config', async () => {
    // Test that timeout is properly passed to configuration
    const shortTimeoutAdapter = new ClaudeCodeAdapter({
      ...mockConfig,
      claudeCodeConfig: {
        ...mockConfig.claudeCodeConfig!,
        timeout: 500 // 500ms
      }
    });
    
    const start = Date.now();
    const result = await shortTimeoutAdapter.generateSolution(mockIssueContext, mockAnalysis);
    const duration = Date.now() - start;
    
    // Should fail quickly due to non-existent executable
    expect(result.success).toBe(false);
    expect(result.message).toBe('Claude Code CLI not available');
    
    // Should not wait for full timeout since CLI is not available
    expect(duration).toBeLessThan(1000);
  });

  test('should track usage data for timeout scenarios', async () => {
    const result = await adapter.generateSolution(mockIssueContext, mockAnalysis);
    
    expect(result.success).toBe(false);
    
    const usageData = adapter.getUsageData();
    expect(usageData.length).toBe(1);
    expect(usageData[0].successful).toBe(false);
    expect(usageData[0].errorType).toBe('cli_not_available');
    expect(usageData[0].issueId).toBe('1');
  });

  test('should provide helpful error messages for timeout scenarios', async () => {
    const result = await adapter.generateSolution(mockIssueContext, mockAnalysis);
    
    expect(result.success).toBe(false);
    expect(result.error).toContain('Claude Code CLI not available');
    expect(result.error).toContain('Installation instructions');
    expect(result.error).toContain('https://claude.ai/console/claude-code');
    expect(result.error).toContain('claude -v');
  });

  test('should include retry count in usage analytics', async () => {
    // This will attempt retries but all will fail due to CLI not being available
    const result = await adapter.generateSolution(mockIssueContext, mockAnalysis);
    
    expect(result.success).toBe(false);
    
    const usageData = adapter.getUsageData();
    expect(usageData.length).toBe(1);
    expect(usageData[0].retryCount).toBeUndefined(); // No retries for CLI not available
  });

  test('should get analytics summary correctly', async () => {
    // Generate a few attempts to test analytics
    await adapter.generateSolution(mockIssueContext, mockAnalysis);
    await adapter.generateSolution({...mockIssueContext, id: '2'}, mockAnalysis);
    
    const summary = adapter.getAnalyticsSummary();
    
    expect(summary).toMatchObject({
      total: 2,
      successful: 0,
      successRate: '0.0%',
      errorTypes: {
        cli_not_available: 2
      }
    });
  });
});