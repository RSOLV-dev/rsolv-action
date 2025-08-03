import { GitBasedClaudeCodeAdapter } from '../claude-code-git';
import { describe, it, expect, beforeEach, afterEach, jest } from 'bun:test';
import * as child_process from 'child_process';

// Create logger spy
const loggerSpy = {
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn()
};

// Mock the logger module
jest.mock('../../../utils/logger');
require('../../../utils/logger').logger = loggerSpy;

// Mock execSync
const mockExecSync = jest.fn();

describe('Debug Conversation Logging', () => {
  let adapter: GitBasedClaudeCodeAdapter;
  let originalEnv: NodeJS.ProcessEnv;
  
  const mockConfig = {
    apiKey: 'test-key',
    baseUrl: 'https://api.anthropic.com',
    model: 'claude-3-opus-20240229',
    maxTokens: 4096,
    temperature: 0.1,
    claudeCodeConfig: {
      useStructuredPhases: true
    }
  };
  
  const mockIssueContext = {
    title: 'Test Issue',
    body: 'Test vulnerability',
    number: 1
  };
  
  const mockAnalysis = {
    complexity: 'simple',
    estimatedTime: 5,
    relatedFiles: ['test.js']
  };
  
  beforeEach(() => {
    originalEnv = process.env;
    process.env = { ...originalEnv };
    loggerSpy.info.mockClear();
    loggerSpy.warn.mockClear();
    loggerSpy.error.mockClear();
    loggerSpy.debug.mockClear();
    mockExecSync.mockClear();
    
    // Mock child_process.execSync
    jest.spyOn(child_process, 'execSync').mockImplementation(mockExecSync as any);
    
    adapter = new GitBasedClaudeCodeAdapter(mockConfig as any, '/test/repo');
  });
  
  afterEach(() => {
    process.env = originalEnv;
  });
  
  describe('RED Phase - Without Debug Flag', () => {
    it('should not log conversations when RSOLV_DEBUG_CONVERSATION is not set', async () => {
      delete process.env.RSOLV_DEBUG_CONVERSATION;
      
      // Mock the parent generateSolution to return messages
      jest.spyOn(adapter as any, 'generateSolution').mockResolvedValue({
        success: true,
        messages: [
          { type: 'text', text: 'Analyzing...' },
          { type: 'tool_use', name: 'Edit', input: { path: 'test.js' } }
        ],
        changes: {}
      });
      
      // Mock git to show no changes
      mockExecSync.mockReturnValue('');
      
      await adapter.generateSolutionWithGit(mockIssueContext as any, mockAnalysis as any);
      
      // Should not have logged warning or conversation
      expect(loggerSpy.warn).not.toHaveBeenCalledWith(
        expect.stringContaining('DEBUG MODE')
      );
      expect(loggerSpy.info).not.toHaveBeenCalledWith(
        expect.stringContaining('CLAUDE CODE CONVERSATION')
      );
    });
    
    it('should not log git debug info when flag is not set', async () => {
      delete process.env.RSOLV_DEBUG_CONVERSATION;
      
      jest.spyOn(adapter as any, 'generateSolution').mockResolvedValue({
        success: true,
        messages: [],
        changes: {}
      });
      
      mockExecSync.mockReturnValue('');
      
      await adapter.generateSolutionWithGit(mockIssueContext as any, mockAnalysis as any);
      
      // Should not log git status details
      expect(loggerSpy.info).not.toHaveBeenCalledWith(
        expect.stringContaining('Git status output:')
      );
      expect(loggerSpy.info).not.toHaveBeenCalledWith(
        expect.stringContaining('Working directory:')
      );
    });
  });
  
  describe('GREEN Phase - With Debug Flag', () => {
    beforeEach(() => {
      process.env.RSOLV_DEBUG_CONVERSATION = 'true';
    });
    
    it('should log warning when debug mode is enabled', async () => {
      jest.spyOn(adapter as any, 'generateSolution').mockResolvedValue({
        success: true,
        messages: [],
        changes: {}
      });
      
      mockExecSync.mockReturnValue('');
      
      await adapter.generateSolutionWithGit(mockIssueContext as any, mockAnalysis as any);
      
      expect(loggerSpy.warn).toHaveBeenCalledWith(
        '⚠️  DEBUG MODE: Conversation logging enabled - DO NOT USE IN PRODUCTION'
      );
    });
    
    it('should log conversation messages when present', async () => {
      const mockMessages = [
        { type: 'text', text: 'Analyzing the vulnerability...' },
        { type: 'tool_use', name: 'Edit', input: { 
          path: '/src/test.js',
          old_string: 'vulnerable code',
          new_string: 'fixed code'
        }},
        { type: 'text', text: 'PHASE 1 COMPLETE: Files have been edited' }
      ];
      
      jest.spyOn(adapter as any, 'generateSolution').mockResolvedValue({
        success: true,
        messages: mockMessages,
        changes: {}
      });
      
      mockExecSync.mockReturnValue('');
      
      await adapter.generateSolutionWithGit(mockIssueContext as any, mockAnalysis as any);
      
      // Should log conversation boundaries
      expect(loggerSpy.info).toHaveBeenCalledWith('=== CLAUDE CODE CONVERSATION START ===');
      expect(loggerSpy.info).toHaveBeenCalledWith('=== CLAUDE CODE CONVERSATION END ===');
      
      // Should log message details
      expect(loggerSpy.info).toHaveBeenCalledWith('Message 1 (text):');
      expect(loggerSpy.info).toHaveBeenCalledWith('  Text: Analyzing the vulnerability...');
      
      expect(loggerSpy.info).toHaveBeenCalledWith('Message 2 (tool_use):');
      expect(loggerSpy.info).toHaveBeenCalledWith('  Tool: Edit');
      expect(loggerSpy.info).toHaveBeenCalledWith('  File: /src/test.js');
      expect(loggerSpy.info).toHaveBeenCalledWith('  Editing: vulnerable code...');
    });
    
    it('should truncate very long text messages', async () => {
      const longText = 'a'.repeat(600);
      
      jest.spyOn(adapter as any, 'generateSolution').mockResolvedValue({
        success: true,
        messages: [
          { type: 'text', text: longText }
        ],
        changes: {}
      });
      
      mockExecSync.mockReturnValue('');
      
      await adapter.generateSolutionWithGit(mockIssueContext as any, mockAnalysis as any);
      
      expect(loggerSpy.info).toHaveBeenCalledWith(
        expect.stringContaining('...[truncated]')
      );
    });
    
    it('should log git status debug information', async () => {
      jest.spyOn(adapter as any, 'generateSolution').mockResolvedValue({
        success: true,
        messages: [],
        changes: {}
      });
      
      // Mock git and system commands
      mockExecSync.mockImplementation((cmd: string) => {
        if (cmd.includes('git status')) return 'M src/test.js\n';
        if (cmd.includes('pwd')) return '/test/repo\n';
        if (cmd.includes('ls -la')) return 'total 8\ndrwxr-xr-x  2 user user 4096 Jan  1 00:00 .\n';
        return '';
      });
      
      await adapter.generateSolutionWithGit(mockIssueContext as any, mockAnalysis as any);
      
      expect(loggerSpy.info).toHaveBeenCalledWith('Git status output: M src/test.js\n');
      expect(loggerSpy.info).toHaveBeenCalledWith('Working directory: /test/repo');
      expect(loggerSpy.info).toHaveBeenCalledWith(
        expect.stringContaining('Files in directory:')
      );
    });
    
    it('should handle git command failures gracefully', async () => {
      jest.spyOn(adapter as any, 'generateSolution').mockResolvedValue({
        success: true,
        messages: [],
        changes: {}
      });
      
      mockExecSync.mockImplementation(() => {
        throw new Error('Git command failed');
      });
      
      await adapter.generateSolutionWithGit(mockIssueContext as any, mockAnalysis as any);
      
      expect(loggerSpy.error).toHaveBeenCalledWith(
        'Failed to get git debug info:',
        expect.any(Error)
      );
    });
  });
  
  describe('REFACTOR - Edge Cases', () => {
    beforeEach(() => {
      process.env.RSOLV_DEBUG_CONVERSATION = 'true';
    });
    
    it('should handle assistant messages with complex content', async () => {
      jest.spyOn(adapter as any, 'generateSolution').mockResolvedValue({
        success: true,
        messages: [
          { 
            type: 'assistant',
            message: {
              content: [
                { type: 'text', text: 'Response' },
                { type: 'tool_use', name: 'Edit' }
              ]
            }
          }
        ],
        changes: {}
      });
      
      mockExecSync.mockReturnValue('');
      
      await adapter.generateSolutionWithGit(mockIssueContext as any, mockAnalysis as any);
      
      expect(loggerSpy.info).toHaveBeenCalledWith(
        '  Assistant message with 2 content items'
      );
    });
    
    it('should only enable debug when explicitly set to "true"', async () => {
      process.env.RSOLV_DEBUG_CONVERSATION = 'false';
      
      jest.spyOn(adapter as any, 'generateSolution').mockResolvedValue({
        success: true,
        messages: [{ type: 'text', text: 'Test' }],
        changes: {}
      });
      
      mockExecSync.mockReturnValue('');
      
      await adapter.generateSolutionWithGit(mockIssueContext as any, mockAnalysis as any);
      
      expect(loggerSpy.warn).not.toHaveBeenCalledWith(
        expect.stringContaining('DEBUG MODE')
      );
    });
  });
});