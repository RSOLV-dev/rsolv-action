import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ElixirASTAnalyzer } from '../elixir-ast-analyzer.js';
import * as crypto from 'crypto';

describe('ElixirASTAnalyzer - Encryption', () => {
  let analyzer: ElixirASTAnalyzer;
  
  const mockConfig = {
    apiUrl: 'http://localhost:4000',
    apiKey: 'test-api-key',
    timeout: 5000,
    debug: true
  };

  beforeEach(() => {
    analyzer = new ElixirASTAnalyzer(mockConfig);
    vi.clearAllMocks();
  });

  afterEach(async () => {
    await analyzer.cleanup();
    vi.resetModules();
  });

  describe('encryption integration', () => {
    it('should encrypt files before sending to API', async () => {
      const files = [
        { path: 'src/auth.js', content: 'const password = "secret";' }
      ];

      // Mock the fetch function to capture the request
      let capturedRequest: any = null;
      global.fetch = vi.fn(async (url: string, options: any) => {
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
              vulnerabilities: []
            }]
          })
        } as Response;
      });

      await analyzer.analyzeFiles(files, {});

      expect(capturedRequest).not.toBeNull();
      expect(capturedRequest.body).toHaveProperty('encryptedPayload');
      expect(capturedRequest.body).toHaveProperty('encryptedKey');
      expect(capturedRequest.body).toHaveProperty('iv');
      expect(capturedRequest.body).toHaveProperty('tag');
      
      // Should not have plain text content
      expect(capturedRequest.body).not.toHaveProperty('files');
      expect(JSON.stringify(capturedRequest.body)).not.toContain('secret');
    });

    it('should use AES-256-GCM encryption', async () => {
      const testContent = 'function vulnerable() { eval(userInput); }';
      const files = [{ path: 'test.js', content: testContent }];

      let encryptedData: any = null;
      global.fetch = vi.fn(async (_url: string, options: any) => {
        encryptedData = JSON.parse(options.body);
        return {
          ok: true,
          json: async () => ({
            requestId: 'test-req',
            session: { sessionId: 'test-session' },
            results: []
          })
        } as Response;
      });

      await analyzer.analyzeFiles(files, {});

      // Verify encryption structure
      expect(encryptedData.encryptedKey).toBeDefined();
      expect(encryptedData.iv).toBeDefined();
      expect(encryptedData.tag).toBeDefined();
      expect(encryptedData.encryptedPayload).toBeDefined();
      
      // IV should be 16 bytes (32 hex chars)
      expect(encryptedData.iv.length).toBe(32);
      
      // Tag should be 16 bytes (32 hex chars)
      expect(encryptedData.tag.length).toBe(32);
    });
  });

  describe('decryption of responses', () => {
    it('should decrypt API responses when encryption is used', async () => {
      const expectedVulnerability = {
        type: 'eval-injection',
        severity: 'high',
        line: 1,
        message: 'Direct eval usage detected'
      };

      // Create a mock encrypted response
      const responseData = {
        file: 'test.js',
        vulnerabilities: [expectedVulnerability]
      };

      // Simulate server-side encryption of response
      const symmetricKey = crypto.randomBytes(32);
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv('aes-256-gcm', symmetricKey, iv);
      
      const encrypted = Buffer.concat([
        cipher.update(JSON.stringify(responseData), 'utf8'),
        cipher.final()
      ]);
      
      const tag = cipher.getAuthTag();

      global.fetch = vi.fn(async () => ({
        ok: true,
        json: async () => ({
          requestId: 'test-req',
          session: { sessionId: 'test-session' },
          encrypted: true,
          encryptedResults: encrypted.toString('base64'),
          iv: iv.toString('hex'),
          tag: tag.toString('hex'),
          symmetricKey: symmetricKey.toString('base64')
        })
      } as Response));

      const result = await analyzer.analyzeFiles(
        [{ path: 'test.js', content: 'eval(x)' }],
        {}
      );

      expect(result.results).toBeDefined();
      expect(result.results.length).toBe(1);
      expect(result.results[0].file).toBe('test.js');
      expect(result.results[0].vulnerabilities[0].type).toBe('eval-injection');
    });
  });
});