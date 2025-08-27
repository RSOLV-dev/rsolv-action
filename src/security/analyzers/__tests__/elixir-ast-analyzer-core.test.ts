import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ElixirASTAnalyzer } from '../elixir-ast-analyzer.js';

describe('ElixirASTAnalyzer - Core Functionality', () => {
  let analyzer: ElixirASTAnalyzer;
  
  const mockConfig = {
    apiUrl: 'http://localhost:4000',
    apiKey: 'test-api-key',
    timeout: 5000
  };

  beforeEach(() => {
    analyzer = new ElixirASTAnalyzer(mockConfig);
    vi.clearAllMocks();
    
    // Default mock for fetch
    global.fetch = vi.fn(async () => ({
      ok: true,
      json: async () => ({
        requestId: 'test-req',
        session: { sessionId: 'test-session' },
        results: []
      })
    } as Response));
  });

  afterEach(async () => {
    await analyzer.cleanup();
    vi.resetModules();
  });

  describe('initialization', () => {
    it('should initialize with config', () => {
      const analyzer = new ElixirASTAnalyzer(mockConfig);
      expect(analyzer).toBeDefined();
      expect((analyzer as any).config).toEqual(mockConfig);
    });

    it('should use environment variables as fallback', () => {
      process.env.RSOLV_API_URL = 'https://api.example.com';
      process.env.RSOLV_API_KEY = 'env-key';
      
      const analyzer = new ElixirASTAnalyzer();
      expect((analyzer as any).config.apiUrl).toBe('https://api.example.com');
      expect((analyzer as any).config.apiKey).toBe('env-key');
      
      delete process.env.RSOLV_API_URL;
      delete process.env.RSOLV_API_KEY;
    });
  });

  describe('file analysis', () => {
    it('should analyze single file', async () => {
      const mockResponse = {
        requestId: 'req-123',
        session: { sessionId: 'session-123' },
        results: [{
          file: 'test.js',
          vulnerabilities: [{
            type: 'xss',
            severity: 'medium',
            line: 10,
            message: 'Potential XSS vulnerability'
          }]
        }]
      };

      global.fetch = vi.fn(async () => ({
        ok: true,
        json: async () => mockResponse
      } as Response));

      const result = await analyzer.analyzeFile('test.js', 'const html = userInput;');
      
      expect(result.vulnerabilities).toHaveLength(1);
      expect(result.vulnerabilities[0].type).toBe('xss');
    });

    it('should handle empty file content', async () => {
      const result = await analyzer.analyzeFile('empty.js', '');
      expect(result.vulnerabilities).toEqual([]);
    });

    it('should handle API errors gracefully', async () => {
      global.fetch = vi.fn(async () => ({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error'
      } as Response));

      const result = await analyzer.analyzeFile('test.js', 'code');
      expect(result.vulnerabilities).toEqual([]);
      expect(result.error).toBeDefined();
    });
  });

  describe('batch file analysis', () => {
    it('should analyze multiple files', async () => {
      const files = [
        { path: 'file1.js', content: 'code1' },
        { path: 'file2.js', content: 'code2' }
      ];

      const mockResponse = {
        requestId: 'batch-req',
        session: { sessionId: 'session-456' },
        results: [
          { file: 'file1.js', vulnerabilities: [] },
          { file: 'file2.js', vulnerabilities: [] }
        ]
      };

      global.fetch = vi.fn(async () => ({
        ok: true,
        json: async () => mockResponse
      } as Response));

      const result = await analyzer.analyzeFiles(files, {});
      
      expect(result.results).toHaveLength(2);
      expect(result.results[0].file).toBe('file1.js');
      expect(result.results[1].file).toBe('file2.js');
    });

    it('should handle empty file list', async () => {
      const result = await analyzer.analyzeFiles([], {});
      expect(result.results).toEqual([]);
    });

    it('should respect file size limits', async () => {
      const largeContent = 'x'.repeat(1024 * 1024 * 2); // 2MB
      const files = [
        { path: 'large.js', content: largeContent }
      ];

      const result = await analyzer.analyzeFiles(files, {});
      expect(result.results[0].skipped).toBe(true);
      expect(result.results[0].reason).toContain('size');
    });
  });

  describe('session management', () => {
    it('should reuse sessions within timeout', async () => {
      let callCount = 0;
      global.fetch = vi.fn(async () => {
        callCount++;
        return {
          ok: true,
          json: async () => ({
            requestId: `req-${callCount}`,
            session: {
              sessionId: 'reused-session',
              expiresAt: new Date(Date.now() + 3600000).toISOString()
            },
            results: []
          })
        } as Response;
      });

      await analyzer.analyzeFile('test1.js', 'code1');
      await analyzer.analyzeFile('test2.js', 'code2');
      
      // Should reuse session, so fetch called twice but session reused
      expect(callCount).toBe(2);
      const sessions = (analyzer as any).sessions;
      expect(sessions.size).toBe(1);
    });

    it('should create new session when expired', async () => {
      let sessionId = 1;
      global.fetch = vi.fn(async () => ({
        ok: true,
        json: async () => ({
          requestId: 'req',
          session: {
            sessionId: `session-${sessionId++}`,
            expiresAt: new Date(Date.now() - 1000).toISOString() // Already expired
          },
          results: []
        })
      } as Response));

      await analyzer.analyzeFile('test1.js', 'code1');
      await analyzer.analyzeFile('test2.js', 'code2');
      
      // Should create new sessions each time
      expect(sessionId).toBe(3);
    });
  });

  describe('cleanup', () => {
    it('should cleanup sessions on cleanup call', async () => {
      await analyzer.analyzeFile('test.js', 'code');
      
      const sessions = (analyzer as any).sessions;
      expect(sessions.size).toBeGreaterThan(0);
      
      await analyzer.cleanup();
      expect(sessions.size).toBe(0);
    });
  });
});