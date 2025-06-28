import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { ElixirASTAnalyzer } from '../elixir-ast-analyzer.js';
import { FileSelectionOptions } from '../types.js';
import { FileSelector } from '../file-selector.js';
import * as crypto from 'crypto';

describe('ElixirASTAnalyzer', () => {
  let analyzer: ElixirASTAnalyzer;
  
  const mockConfig = {
    apiUrl: 'http://localhost:4000',
    apiKey: 'test-api-key',
    timeout: 5000,
    debug: true
  };

  beforeEach(() => {
    analyzer = new ElixirASTAnalyzer(mockConfig);
  });

  afterEach(async () => {
    await analyzer.cleanup();
  });

  describe('encryption integration', () => {
    it('should encrypt files before sending to API', async () => {
      const files = [
        { path: 'src/auth.js', content: 'const password = "secret";' }
      ];

      // Mock the fetch function to capture the request
      let capturedRequest: any = null;
      global.fetch = async (url: string, options: any) => {
        capturedRequest = {
          url,
          options,
          body: JSON.parse(options.body)
        };

        // Return mock response
        return {
          ok: true,
          json: async () => ({
            requestId: capturedRequest.body.requestId,
            session: {
              sessionId: 'test-session-123',
              expiresAt: new Date(Date.now() + 3600000).toISOString()
            },
            results: [{
              file: files[0].path,
              status: 'success',
              language: 'javascript',
              patterns: []
            }],
            summary: {
              filesAnalyzed: 1,
              filesWithFindings: 0,
              totalFindings: 0,
              findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
              findingsByLanguage: { javascript: 0 },
              performance: { avgParseTimeMs: 10, totalTimeMs: 10 }
            }
          })
        } as any;
      };

      const response = await analyzer.analyze(files);

      // Verify request was made
      expect(capturedRequest).toBeTruthy();
      expect(capturedRequest.url).toBe('http://localhost:4000/api/v1/ast/analyze');
      
      // Verify authentication
      expect(capturedRequest.options.headers['Authorization']).toBe('Bearer test-api-key');
      
      // Verify encryption key was sent
      const encryptionKeyHeader = capturedRequest.options.headers['X-Encryption-Key'];
      expect(encryptionKeyHeader).toBeTruthy();
      
      // Verify files were encrypted
      const requestBody = capturedRequest.body;
      expect(requestBody.files.length).toBe(1);
      
      const encryptedFile = requestBody.files[0];
      expect(encryptedFile.path).toBe('src/auth.js');
      expect(encryptedFile.encryptedContent).toBeTruthy();
      expect(encryptedFile.encryption.iv).toBeTruthy();
      expect(encryptedFile.encryption.authTag).toBeTruthy();
      expect(encryptedFile.encryption.algorithm).toBe('aes-256-gcm');
      
      // Verify we can decrypt the content
      const keyBuffer = Buffer.from(encryptionKeyHeader, 'base64');
      const iv = Buffer.from(encryptedFile.encryption.iv, 'base64');
      const authTag = Buffer.from(encryptedFile.encryption.authTag, 'base64');
      const encrypted = Buffer.from(encryptedFile.encryptedContent, 'base64');
      
      const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuffer, iv);
      decipher.setAuthTag(authTag);
      
      const decrypted = Buffer.concat([
        decipher.update(encrypted),
        decipher.final()
      ]).toString('utf8');
      
      expect(decrypted).toBe('const password = "secret";');
    });

    it('should handle multiple files with different languages', async () => {
      const files = [
        { path: 'src/auth.js', content: 'const token = "abc";' },
        { path: 'lib/user.ex', content: 'defmodule User do\nend' },
        { path: 'app.py', content: 'import os\npassword = os.getenv("PASSWORD")' }
      ];

      let capturedRequest: any = null;
      global.fetch = async (url: string, options: any) => {
        capturedRequest = JSON.parse(options.body);
        return {
          ok: true,
          json: async () => ({
            requestId: capturedRequest.requestId,
            session: { sessionId: 'test-123', expiresAt: new Date().toISOString() },
            results: files.map(f => ({
              file: f.path,
              status: 'success',
              language: analyzer['detectLanguage'](f.path),
              patterns: []
            })),
            summary: {
              filesAnalyzed: 3,
              filesWithFindings: 0,
              totalFindings: 0,
              findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
              findingsByLanguage: { javascript: 1, elixir: 1, python: 1 },
              performance: { avgParseTimeMs: 10, totalTimeMs: 30 }
            }
          })
        } as any;
      };

      const response = await analyzer.analyze(files);
      
      expect(response.results.length).toBe(3);
      expect(capturedRequest.files.length).toBe(3);
      
      // Verify language detection
      expect(capturedRequest.files[0].metadata.language).toBe('javascript');
      expect(capturedRequest.files[1].metadata.language).toBe('elixir');
      expect(capturedRequest.files[2].metadata.language).toBe('python');
      
      // Verify all files are encrypted
      for (const file of capturedRequest.files) {
        expect(file.encryptedContent).toBeTruthy();
        expect(file.encryption.iv).toBeTruthy();
        expect(file.encryption.authTag).toBeTruthy();
      }
    });

    it('should generate correct content hash', async () => {
      const content = 'test content with special chars: 你好 🚀';
      const files = [{ path: 'test.js', content }];

      let capturedRequest: any = null;
      global.fetch = async (url: string, options: any) => {
        capturedRequest = JSON.parse(options.body);
        return {
          ok: true,
          json: async () => ({
            requestId: capturedRequest.requestId,
            session: { sessionId: 'test-123', expiresAt: new Date().toISOString() },
            results: [{ file: 'test.js', status: 'success', language: 'javascript', patterns: [] }],
            summary: {
              filesAnalyzed: 1,
              filesWithFindings: 0,
              totalFindings: 0,
              findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
              findingsByLanguage: { javascript: 1 },
              performance: { avgParseTimeMs: 10, totalTimeMs: 10 }
            }
          })
        } as any;
      };

      await analyzer.analyze(files);
      
      const expectedHash = crypto.createHash('sha256').update(content).digest('hex');
      expect(capturedRequest.files[0].metadata.contentHash).toBe(expectedHash);
    });

    it('should reuse session ID across requests', async () => {
      const requests: any[] = [];
      
      global.fetch = async (url: string, options: any) => {
        const body = JSON.parse(options.body);
        requests.push(body);
        
        return {
          ok: true,
          json: async () => ({
            requestId: body.requestId,
            session: {
              sessionId: 'reusable-session-456',
              expiresAt: new Date(Date.now() + 3600000).toISOString()
            },
            results: [],
            summary: {
              filesAnalyzed: 0,
              filesWithFindings: 0,
              totalFindings: 0,
              findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
              findingsByLanguage: {},
              performance: { avgParseTimeMs: 0, totalTimeMs: 0 }
            }
          })
        } as any;
      };

      // First request - no session ID
      await analyzer.analyze([{ path: 'test1.js', content: 'test1' }]);
      expect(requests[0].sessionId).toBeUndefined();
      
      // Second request - should reuse session ID
      await analyzer.analyze([{ path: 'test2.js', content: 'test2' }]);
      expect(requests[1].sessionId).toBe('reusable-session-456');
    });

    it('should handle encryption key rotation', async () => {
      const files = [{ path: 'test.js', content: 'content' }];
      const encryptionKeys: string[] = [];

      global.fetch = async (url: string, options: any) => {
        encryptionKeys.push(options.headers['X-Encryption-Key']);
        return {
          ok: true,
          json: async () => ({
            requestId: JSON.parse(options.body).requestId,
            session: { sessionId: 'test', expiresAt: new Date().toISOString() },
            results: [],
            summary: {
              filesAnalyzed: 1,
              filesWithFindings: 0,
              totalFindings: 0,
              findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
              findingsByLanguage: {},
              performance: { avgParseTimeMs: 0, totalTimeMs: 0 }
            }
          })
        } as any;
      };

      // Make two requests
      await analyzer.analyze(files);
      const key1 = encryptionKeys[0];
      
      // Create new analyzer instance (simulates key rotation)
      const analyzer2 = new ElixirASTAnalyzer(mockConfig);
      await analyzer2.analyze(files);
      const key2 = encryptionKeys[1];
      
      // Keys should be different
      expect(key1).not.toBe(key2);
      
      // But both should be valid 256-bit keys
      expect(Buffer.from(key1, 'base64').length).toBe(32);
      expect(Buffer.from(key2, 'base64').length).toBe(32);
    });
  });

  describe('error handling', () => {
    it('should handle API errors gracefully', async () => {
      global.fetch = async () => {
        return {
          ok: false,
          status: 401,
          statusText: 'Unauthorized',
          json: async () => ({
            error: {
              code: 'INVALID_API_KEY',
              message: 'Invalid API key provided'
            }
          })
        } as any;
      };

      await expect(
        analyzer.analyze([{ path: 'test.js', content: 'test' }])
      ).rejects.toThrow('Invalid API key provided');
    });

    it('should handle timeouts', async () => {
      const slowAnalyzer = new ElixirASTAnalyzer({
        ...mockConfig,
        timeout: 100 // 100ms timeout
      });

      global.fetch = async (url: string, options: any) => {
        // Check for abort signal
        if (options.signal) {
          return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
              resolve({ ok: true, json: async () => ({}) } as any);
            }, 200);
            
            options.signal.addEventListener('abort', () => {
              clearTimeout(timeout);
              const error = new Error('The operation was aborted');
              error.name = 'AbortError';
              reject(error);
            });
          });
        }
        return { ok: true, json: async () => ({}) } as any;
      };

      await expect(
        slowAnalyzer.analyze([{ path: 'test.js', content: 'test' }])
      ).rejects.toThrow('Request timeout');
    });
  });

  describe('health check', () => {
    it('should check service health', async () => {
      global.fetch = async (url: string) => {
        expect(url).toBe('http://localhost:4000/health');
        return { ok: true } as any;
      };

      const isHealthy = await analyzer.healthCheck();
      expect(isHealthy).toBe(true);
    });

    it('should handle health check failures', async () => {
      global.fetch = async () => {
        throw new Error('Network error');
      };

      const isHealthy = await analyzer.healthCheck();
      expect(isHealthy).toBe(false);
    });
  });

  describe('vulnerability extraction', () => {
    it('should extract vulnerabilities from response', () => {
      const response = {
        requestId: 'test-123',
        session: { sessionId: 'test', expiresAt: new Date().toISOString() },
        results: [
          {
            file: 'src/auth.js',
            status: 'success' as const,
            language: 'javascript',
            patterns: [
              {
                pattern: {
                  id: 'sql-injection',
                  name: 'SQL Injection',
                  description: 'SQL injection vulnerability',
                  type: 'sql_injection',
                  severity: 'high' as const,
                  message: 'User input in SQL query'
                },
                location: {
                  start: { line: 10, column: 5 },
                  end: { line: 10, column: 50 }
                },
                confidence: 0.95
              }
            ]
          }
        ],
        summary: {
          filesAnalyzed: 1,
          filesWithFindings: 1,
          totalFindings: 1,
          findingsBySeverity: { critical: 0, high: 1, medium: 0, low: 0 },
          findingsByLanguage: { javascript: 1 },
          performance: { avgParseTimeMs: 15, totalTimeMs: 15 }
        }
      };

      const vulnerabilities = analyzer.extractVulnerabilities(response);
      
      expect(vulnerabilities.length).toBe(1);
      expect(vulnerabilities[0].file).toBe('src/auth.js');
      expect(vulnerabilities[0].type).toBe('sql_injection');
      expect(vulnerabilities[0].severity).toBe('high');
      expect(vulnerabilities[0].message).toBe('User input in SQL query');
      expect(vulnerabilities[0].line).toBe(10);
      expect(vulnerabilities[0].column).toBe(5);
    });
  });
});