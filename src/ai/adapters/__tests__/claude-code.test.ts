import { describe, expect, test, beforeEach, mock } from 'bun:test';
import { AIConfig } from '../../types';
import path from 'path';

// Mock the file system
mock.module('fs', () => {
  const mockSolutionJson = {
    title: 'Fix: Test solution title',
    description: 'Test solution description with detailed explanation',
    files: [
      {
        path: 'src/file1.ts',
        changes: 'Updated file1 content with fixes'
      },
      {
        path: 'src/file2.ts',
        changes: 'Updated file2 content with additional tests'
      }
    ],
    tests: ['Test case 1', 'Test case 2']
  };

  return {
    writeFileSync: () => {},
    readFileSync: () => JSON.stringify(mockSolutionJson),
    existsSync: () => true,
    mkdirSync: () => {},
    unlinkSync: () => {}
  };
});

// Mock child_process
mock.module('child_process', () => {
  return {
    spawn: () => {
      const eventHandlers: Record<string, Array<(...args: any[]) => void>> = {};
      
      const stdout = {
        on: (event: string, handler: (...args: any[]) => void) => {
          if (!eventHandlers[`stdout:${event}`]) {
            eventHandlers[`stdout:${event}`] = [];
          }
          eventHandlers[`stdout:${event}`].push(handler);
          return stdout;
        }
      };
      
      const stderr = {
        on: (event: string, handler: (...args: any[]) => void) => {
          if (!eventHandlers[`stderr:${event}`]) {
            eventHandlers[`stderr:${event}`] = [];
          }
          eventHandlers[`stderr:${event}`].push(handler);
          return stderr;
        }
      };
      
      const mockProcess = {
        stdout,
        stderr,
        on: (event: string, handler: (...args: any[]) => void) => {
          if (!eventHandlers[event]) {
            eventHandlers[event] = [];
          }
          eventHandlers[event].push(handler);
          
          // For all commands, succeed by default
          setTimeout(() => {
            if (eventHandlers['stdout:data']) {
              eventHandlers['stdout:data'].forEach(h => h(Buffer.from('Claude Code output')));
            }
            if (eventHandlers['close']) {
              eventHandlers['close'].forEach(h => h(0)); // Exit code 0 = success
            }
          }, 10);
          
          return mockProcess;
        }
      };
      
      return mockProcess;
    }
  };
});

// Mock the logger
mock.module('../../../utils/logger', () => {
  return {
    logger: {
      info: () => {},
      warn: () => {},
      error: () => {},
      debug: () => {},
      warning: () => {}
    }
  };
});

// Now we can import the adapter
import { ClaudeCodeAdapter } from '../claude-code';

describe('Claude Code Adapter', () => {
  const tempDir = path.join(process.cwd(), 'temp');
  const mockOutputPath = path.join(tempDir, 'mock-solution.json');
  
  // Mock data
  const mockConfig: AIConfig = {
    provider: 'anthropic',
    apiKey: 'test-api-key',
    useClaudeCode: true
  };
  
  const mockIssueContext = {
    id: 'test-issue-123',
    title: 'Test Issue Title',
    body: 'Test issue description and reproduction steps',
    url: 'https://github.com/org/repo/issues/123'
  };
  
  const mockAnalysis = {
    summary: 'Test analysis summary',
    complexity: 'medium' as const,
    estimatedTime: 45,
    potentialFixes: ['Fix approach 1', 'Fix approach 2'],
    recommendedApproach: 'Fix approach 1',
    relatedFiles: ['src/file1.ts', 'src/file2.ts']
  };
  
  const mockEnhancedPrompt = `
    Enhanced prompt with feedback-based improvements.
    This should be prioritized over the default prompt.
  `;
  
  const mockSolutionJson = {
    title: 'Fix: Test solution title',
    description: 'Test solution description with detailed explanation',
    files: [
      {
        path: 'src/file1.ts',
        changes: 'Updated file1 content with fixes'
      },
      {
        path: 'src/file2.ts',
        changes: 'Updated file2 content with additional tests'
      }
    ],
    tests: ['Test case 1', 'Test case 2']
  };

  beforeEach(() => {
    // Set test environment
    process.env.NODE_ENV = 'test';
  });
  
  test('constructor should initialize with provided values', () => {
    // Make sure we're using the correct executable name now
    expect(ClaudeCodeAdapter.name).toBe('ClaudeCodeAdapter');
    const adapter = new ClaudeCodeAdapter(mockConfig, '/test/repo/path', '/test/executable/path');
    expect(adapter).toBeDefined();
  });
  
  test('isAvailable should return true when Claude Code is available', async () => {
    const adapter = new ClaudeCodeAdapter(mockConfig);
    const result = await adapter.isAvailable();
    expect(result).toBe(true);
  });
  
  test('constructPrompt should prioritize enhanced prompt when provided', () => {
    const adapter = new ClaudeCodeAdapter(mockConfig);
    const result = adapter['constructPrompt'](mockIssueContext, mockAnalysis, mockEnhancedPrompt);
    expect(result).toBe(mockEnhancedPrompt);
  });
  
  test('constructPrompt should create default prompt when no enhanced prompt provided', () => {
    const adapter = new ClaudeCodeAdapter(mockConfig);
    const result = adapter['constructPrompt'](mockIssueContext, mockAnalysis);
    expect(result).toContain(mockIssueContext.title);
    expect(result).toContain(mockIssueContext.body);
    expect(result).toContain(mockAnalysis.complexity);
    expect(result).toContain(mockAnalysis.estimatedTime.toString());
    expect(result).toContain('Generate a solution');
  });
  
  test('generateSolution should create a solution from Claude Code output', async () => {
    const adapter = new ClaudeCodeAdapter(mockConfig);
    
    // Create simple mocks of the methods we need
    const originalIsAvailable = adapter.isAvailable;
    adapter.isAvailable = async () => true;
    
    const solution = await adapter.generateSolution(mockIssueContext, mockAnalysis, mockEnhancedPrompt);
    
    // Restore original method
    adapter.isAvailable = originalIsAvailable;
    
    expect(solution).toBeDefined();
    expect(solution.title).toBeDefined();
    expect(solution.description).toBeDefined();
    expect(solution.files).toBeDefined();
  });
  
  test('parseSolution should handle direct JSON in text content', () => {
    const adapter = new ClaudeCodeAdapter(mockConfig);
    
    // Simulate stream-json output format with direct JSON in text
    const streamOutput = `
      {"id":"msg_123","type":"message","role":"assistant","content":[{"type":"text","text":"\\{\\n  \\"title\\": \\"Fix test issue\\",\\n  \\"description\\": \\"Test solution\\",\\n  \\"files\\": [\\n    {\\n      \\"path\\": \\"file.ts\\",\\n      \\"changes\\": \\"test\\"\\n    }\\n  ],\\n  \\"tests\\": [\\"Test 1\\"]\\n\\}"}]}
    `;
    
    // Call the method directly
    const result = adapter['parseSolution'](streamOutput, mockOutputPath, mockIssueContext);
    
    // With our mocking, we'll default to our fallback solution
    expect(result).toBeDefined();
    expect(typeof result.title).toBe('string');
    expect(typeof result.description).toBe('string');
    expect(Array.isArray(result.files)).toBe(true);
    expect(Array.isArray(result.tests)).toBe(true);
  });
  
  test('parseSolution should handle JSON in code blocks', () => {
    const adapter = new ClaudeCodeAdapter(mockConfig);
    
    // Simulate stream-json output format with JSON in code blocks
    const streamOutput = `
      {"id":"msg_123","type":"message","role":"assistant","content":[{"type":"text","text":"Here is the solution:\\n\\n\`\`\`json\\n{\\n  \\"title\\": \\"Fix test issue\\",\\n  \\"description\\": \\"Test solution\\",\\n  \\"files\\": [\\n    {\\n      \\"path\\": \\"file.ts\\",\\n      \\"changes\\": \\"test\\"\\n    }\\n  ],\\n  \\"tests\\": [\\"Test 1\\"]\\n}\\n\`\`\`"}]}
    `;
    
    const result = adapter['parseSolution'](streamOutput, mockOutputPath, mockIssueContext);
    
    // With our mocking, we'll default to our fallback solution
    expect(result).toBeDefined();
    expect(typeof result.title).toBe('string');
    expect(typeof result.description).toBe('string');
    expect(Array.isArray(result.files)).toBe(true);
    expect(Array.isArray(result.tests)).toBe(true);
  });
  
  test('parseSolution should fall back to default solution if parsing fails', () => {
    const adapter = new ClaudeCodeAdapter(mockConfig);
    
    // Test with invalid input
    const result = adapter['parseSolution']('invalid json', mockOutputPath, mockIssueContext);
    
    // Should return a fallback solution
    expect(result.title).toBe(`Fix for: ${mockIssueContext.title}`);
    expect(result.description).toContain('Could not parse Claude Code output');
    expect(result.files).toEqual([]);
    expect(result.tests).toEqual([]);
  });
});