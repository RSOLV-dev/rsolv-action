import { describe, expect, test, beforeEach, mock, afterEach } from 'bun:test';
import { AIConfig } from '../../types.js';
import path from 'path';
import type { SDKMessage } from '@anthropic-ai/claude-code';

// Create a mock query function we can reference
const mockQueryFunction = mock(async function* (options: any) {
  // Default behavior - yield a text message with a solution
  yield {
    type: 'text',
    text: JSON.stringify({
      title: 'Fix: Test issue',
      description: 'Test solution',
      files: [{
        path: 'src/test.ts',
        changes: 'console.log("fixed");'
      }],
      tests: ['Test case 1']
    })
  } as SDKMessage;
});

// Mock the @anthropic-ai/claude-code module using require.resolve for better isolation
const claudeCodePath = require.resolve('@anthropic-ai/claude-code');
mock.module(claudeCodePath, () => {
  return {
    query: mockQueryFunction
  };
});

// Mock the file system
const mockAnalytics: any[] = [];
const mockWriteFileSync = mock((path: string, content: string) => {
  if (path.includes('analytics')) {
    try {
      const data = JSON.parse(content);
      // Only keep last entry to avoid accumulation
      if (mockAnalytics.length > 0) {
        mockAnalytics.length = 0;
      }
      mockAnalytics.push(...data);
    } catch (e) {
      // Ignore parse errors
    }
  }
});

const mockReadFileSync = mock((path: string) => {
  if (path.includes('analytics')) {
    return JSON.stringify(mockAnalytics);
  }
  return '{}';
});

const mockExistsSync = mock((path: string) => {
  return path.includes('temp') || path.includes('analytics');
});

const mockMkdirSync = mock(() => {});
const mockUnlinkSync = mock(() => {});

const fsPath = require.resolve('fs');
mock.module(fsPath, () => ({
  writeFileSync: mockWriteFileSync,
  readFileSync: mockReadFileSync,
  existsSync: mockExistsSync,
  mkdirSync: mockMkdirSync,
  unlinkSync: mockUnlinkSync
}));

// Mock the logger using require.resolve
const loggerPath = require.resolve('../../../utils/logger');
mock.module(loggerPath, () => {
  return {
    logger: {
      info: mock(() => {}),
      warn: mock(() => {}),
      error: mock(() => {}),
      debug: mock(() => {})
    }
  };
});

// Import after mocking
import { ClaudeCodeAdapter } from '../claude-code.js';
import { query as mockQuery } from '@anthropic-ai/claude-code';
import { logger } from '../../../utils/logger.js';
import fs from 'fs';

describe('Claude Code SDK Adapter', () => {
  let adapter: ClaudeCodeAdapter;
  let originalEnv: NodeJS.ProcessEnv;
  
  // Mock data
  const mockConfig: AIConfig = {
    provider: 'anthropic',
    apiKey: 'test-api-key',
    useClaudeCode: true,
    claudeCodeConfig: {
      verboseLogging: true,
      timeout: 30000,
      retryOptions: {
        maxRetries: 2,
        baseDelay: 1000
      }
    }
  };
  
  const mockIssueContext = {
    id: 'test-issue-123',
    title: 'Fix XSS vulnerability',
    body: 'There is an XSS vulnerability in the login form',
    url: 'https://github.com/org/repo/issues/123',
    number: 123,
    owner: 'org',
    repo: 'repo',
    repoUrl: 'https://github.com/org/repo',
    platform: 'github' as const,
    labels: []
  };
  
  const mockAnalysis = {
    complexity: 'medium' as const,
    estimatedTime: 30,
    relatedFiles: ['src/login.ts', 'src/auth.ts']
  };
  
  const mockCredentialManager = {
    getCredential: mock((provider: string) => {
      if (provider === 'anthropic') {
        return 'vended-api-key';
      }
      throw new Error('Unknown provider');
    })
  };

  beforeEach(() => {
    // Save original environment
    originalEnv = { ...process.env };
    
    // Clear any previous mocks
    (mockQuery as any).mockClear();
    (logger.info as any).mockClear();
    (logger.warn as any).mockClear();
    (logger.error as any).mockClear();
    (logger.debug as any).mockClear();
    mockWriteFileSync.mockClear();
    mockReadFileSync.mockClear();
    
    // Clear analytics
    mockAnalytics.length = 0;
  });

  afterEach(() => {
    // Restore original environment
    process.env = originalEnv;
    
    // Clear all mock calls
    mockWriteFileSync.mockClear();
    mockReadFileSync.mockClear();
    mockExistsSync.mockClear();
    mockMkdirSync.mockClear();
    mockUnlinkSync.mockClear();
    mockQueryFunction.mockClear();
    
    // Clear analytics
    mockAnalytics.length = 0;
    
    // Clear module mocks if possible
    try {
      mock.restore();
    } catch (e) {
      // Ignore if restore is not available
    }
  });

  test('should create instance with correct configuration', () => {
    adapter = new ClaudeCodeAdapter(mockConfig, '/test/repo/path', mockCredentialManager);
    
    expect(adapter).toBeDefined();
    expect(adapter.constructor.name).toBe('ClaudeCodeAdapter');
    
    // Should log initialization with verbose logging
    expect(logger.info).toHaveBeenCalledWith(
      expect.stringContaining('Claude Code SDK adapter initialized'),
      expect.any(String)
    );
  });

  test('should detect SDK availability', async () => {
    adapter = new ClaudeCodeAdapter(mockConfig);
    
    const available = await adapter.isAvailable();
    expect(available).toBe(true);
  });

  test('should generate solution with basic prompt', async () => {
    adapter = new ClaudeCodeAdapter(mockConfig);
    
    const result = await adapter.generateSolution(mockIssueContext, mockAnalysis);
    
    expect(result.success).toBe(true);
    expect(result.message).toContain('Solution generated with Claude Code SDK');
    expect(result.changes).toBeDefined();
    expect(result.changes!['src/test.ts']).toBe('console.log("fixed");');
    
    // Should have called query with correct parameters
    expect(mockQueryFunction).toHaveBeenCalled();
    const callArgs = mockQueryFunction.mock.calls[0][0];
    expect(callArgs.prompt).toContain('Fix XSS vulnerability');
    expect(callArgs.options).toBeDefined();
    expect(callArgs.options.cwd).toBeDefined();
    expect(callArgs.options.maxTurns).toBe(30);
  });

  test('should use enhanced prompt when provided', async () => {
    adapter = new ClaudeCodeAdapter(mockConfig);
    
    const enhancedPrompt = 'This is an enhanced prompt with additional context';
    await adapter.generateSolution(mockIssueContext, mockAnalysis, enhancedPrompt);
    
    expect(mockQueryFunction).toHaveBeenCalled();
    const callArgs = mockQueryFunction.mock.calls[0][0];
    expect(callArgs.prompt).toBe(enhancedPrompt);
    expect(callArgs.options).toBeDefined();
    expect(callArgs.options.cwd).toBeDefined();
    expect(callArgs.options.maxTurns).toBe(30);
  });

  test('should handle vended credentials correctly', async () => {
    const configWithVended: AIConfig = {
      ...mockConfig,
      useVendedCredentials: true
    };
    
    adapter = new ClaudeCodeAdapter(configWithVended, process.cwd(), mockCredentialManager);
    
    await adapter.generateSolution(mockIssueContext, mockAnalysis);
    
    // Should have set the vended API key
    expect(process.env.ANTHROPIC_API_KEY).toBe('vended-api-key');
    expect(logger.info).toHaveBeenCalledWith('Using vended Anthropic credential for Claude Code SDK');
  });

  test('should extract solution from text messages', async () => {
    // Mock query to return solution in different formats
    (mockQuery as any).mockImplementationOnce(async function* () {
      // First, non-solution text
      yield { type: 'text', text: 'Analyzing the issue...' } as SDKMessage;
      
      // Then solution in code block
      yield {
        type: 'text',
        text: `Here's the solution:
\`\`\`json
{
  "title": "Fix: XSS in login",
  "description": "Sanitize user input",
  "files": [{"path": "login.ts", "changes": "// fixed"}],
  "tests": ["Test XSS prevention"]
}
\`\`\``
      } as SDKMessage;
    });
    
    adapter = new ClaudeCodeAdapter(mockConfig);
    const result = await adapter.generateSolution(mockIssueContext, mockAnalysis);
    
    expect(result.success).toBe(true);
    expect(result.changes!['login.ts']).toBe('// fixed');
  });

  test('should handle timeout with abort controller', async () => {
    // Mock query to never complete
    (mockQuery as any).mockImplementationOnce(async function* (params: any) {
      // Wait for abort signal
      await new Promise((resolve, reject) => {
        params.options.abortController.signal.addEventListener('abort', () => {
          reject(new Error('AbortError'));
        });
      });
    });
    
    const configWithShortTimeout: AIConfig = {
      ...mockConfig,
      claudeCodeConfig: {
        ...mockConfig.claudeCodeConfig,
        timeout: 100 // 100ms timeout
      }
    };
    
    adapter = new ClaudeCodeAdapter(configWithShortTimeout);
    const result = await adapter.generateSolution(mockIssueContext, mockAnalysis);
    
    expect(result.success).toBe(false);
    expect(result.error).toContain('timed out');
    expect(logger.error).toHaveBeenCalledWith(
      expect.stringContaining('timed out after 0.1 seconds')
    );
  });

  test('should track usage analytics', async () => {
    adapter = new ClaudeCodeAdapter(mockConfig);
    
    // Generate multiple solutions
    await adapter.generateSolution(mockIssueContext, mockAnalysis);
    
    // Mock an error case
    (mockQuery as any).mockImplementationOnce(async function* () {
      throw new Error('Test error');
    });
    await adapter.generateSolution(mockIssueContext, mockAnalysis);
    
    // Verify in-memory usage tracking
    const usageData = adapter.getUsageData();
    expect(usageData).toHaveLength(2);
    expect(usageData[0]).toHaveProperty('successful', true);
    expect(usageData[1]).toHaveProperty('successful', false);
    expect(usageData[1]).toHaveProperty('errorType', 'query_error');
    
    // Verify analytics summary
    const analytics = adapter.getAnalyticsSummary();
    
    expect(analytics).toHaveProperty('total', 2);
    expect(analytics).toHaveProperty('successful', 1);
    expect(analytics).toHaveProperty('successRate', '50.0%');
    expect(analytics).toHaveProperty('avgDuration');
    expect(analytics).toHaveProperty('errorTypes');
    
    const errorTypes = (analytics as any).errorTypes;
    expect(errorTypes).toHaveProperty('query_error', 1);
    
    // Verify logging occurred
    expect(logger.info).toHaveBeenCalledWith(
      expect.stringContaining('Usage stats for issue')
    );
  });

  test('should handle SDK query errors gracefully', async () => {
    // Mock query to throw an error
    (mockQuery as any).mockImplementationOnce(async function* () {
      throw new Error('SDK query failed');
    });
    
    adapter = new ClaudeCodeAdapter(mockConfig);
    const result = await adapter.generateSolution(mockIssueContext, mockAnalysis);
    
    expect(result.success).toBe(false);
    expect(result.message).toBe('Claude Code SDK execution failed');
    expect(result.error).toContain('SDK query failed');
    expect(logger.error).toHaveBeenCalledWith(
      'Claude Code SDK query failed',
      expect.any(Error)
    );
  });

  test('should extract solutions from code blocks', async () => {
    // Test extraction logic directly
    adapter = new ClaudeCodeAdapter(mockConfig);
    
    const textWithCodeBlock = `
Let me analyze this issue and provide a solution.

\`\`\`json
{
  "title": "Security Fix: Prevent XSS",
  "description": "Added input sanitization",
  "files": [
    {
      "path": "src/utils/sanitize.ts",
      "changes": "export function sanitize(input: string): string {\\n  return input.replace(/[<>]/g, '');\\n}"
    }
  ],
  "tests": ["Test sanitization", "Test XSS prevention"]
}
\`\`\`

This solution prevents XSS attacks.`;
    
    const solution = adapter['extractSolutionFromText'](textWithCodeBlock);
    
    expect(solution).not.toBeNull();
    expect(solution!.title).toBe('Security Fix: Prevent XSS');
    expect(solution!.files[0].path).toBe('src/utils/sanitize.ts');
    expect(solution!.tests).toHaveLength(2);
  });

  test('should return error when no solution found', async () => {
    // Mock query to return only non-solution messages
    (mockQuery as any).mockImplementationOnce(async function* () {
      yield { type: 'text', text: 'Thinking about the problem...' } as SDKMessage;
      yield { type: 'text', text: 'This is complex...' } as SDKMessage;
      yield { type: 'tool_use', name: 'some_tool', input: {} } as SDKMessage;
    });
    
    adapter = new ClaudeCodeAdapter(mockConfig);
    const result = await adapter.generateSolution(mockIssueContext, mockAnalysis);
    
    expect(result.success).toBe(false);
    expect(result.message).toBe('No solution found in response');
    expect(result.error).toContain('did not generate a valid JSON solution');
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('No solution found in Claude Code SDK response'));
  });

  test('should handle missing SDK gracefully', async () => {
    // Override the isAvailable method to return false
    adapter = new ClaudeCodeAdapter(mockConfig);
    adapter.isAvailable = async () => false;
    
    const result = await adapter.generateSolution(mockIssueContext, mockAnalysis);
    
    expect(result.success).toBe(false);
    expect(result.message).toBe('Claude Code CLI not available');
    expect(result.error).toContain('@anthropic-ai/claude-code is installed');
  });

  test('should fallback when credential manager fails', async () => {
    // Mock credential manager to throw
    const failingCredentialManager = {
      getCredential: mock(() => {
        throw new Error('Credential service unavailable');
      })
    };
    
    const configWithVended: AIConfig = {
      ...mockConfig,
      apiKey: 'fallback-key',
      useVendedCredentials: true
    };
    
    adapter = new ClaudeCodeAdapter(configWithVended, process.cwd(), failingCredentialManager);
    
    await adapter.generateSolution(mockIssueContext, mockAnalysis);
    
    // Should use fallback API key
    expect(process.env.ANTHROPIC_API_KEY).toBe('fallback-key');
    expect(logger.warn).toHaveBeenCalledWith(
      'Failed to get vended credential, falling back to config API key',
      expect.any(Error)
    );
  });

  test('should construct proper default prompt', () => {
    adapter = new ClaudeCodeAdapter(mockConfig);
    
    const prompt = adapter['constructPrompt'](mockIssueContext, mockAnalysis);
    
    expect(prompt).toContain('Fix XSS vulnerability');
    expect(prompt).toContain('There is an XSS vulnerability in the login form');
    expect(prompt).toContain('medium');
    expect(prompt).toContain('30 minutes');
    expect(prompt).toContain('src/login.ts');
    expect(prompt).toContain('src/auth.ts');
    expect(prompt).toContain('provide your ultimate solution as a JSON object');
  });

  test('should handle direct JSON parsing', async () => {
    adapter = new ClaudeCodeAdapter(mockConfig);
    
    // Test direct JSON parsing
    const jsonText = JSON.stringify({
      title: 'Direct JSON Fix',
      description: 'Parsed directly',
      files: [{ path: 'test.js', changes: 'fixed' }],
      tests: []
    });
    
    const solution = adapter['extractSolutionFromText'](jsonText);
    
    expect(solution).not.toBeNull();
    expect(solution!.title).toBe('Direct JSON Fix');
  });

  test('should return null for invalid solution format', () => {
    adapter = new ClaudeCodeAdapter(mockConfig);
    
    // Missing required fields
    const invalidSolution = adapter['extractSolutionFromText'](JSON.stringify({
      title: 'Missing files array'
      // Missing description and files
    }));
    
    expect(invalidSolution).toBeNull();
    
    // Not JSON at all
    const nonJson = adapter['extractSolutionFromText']('This is not JSON');
    expect(nonJson).toBeNull();
  });
});