import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { SecurityDetectorV2 } from '../security/detector-v2';
import { PatternApiClient } from '../security/pattern-api-client';
import type { SecurityPattern, SecurityIssue } from '../security/types';

// Mock server to simulate the pattern API
import { createServer, Server } from 'http';

describe('Pattern API E2E Integration', () => {
  let server: Server;
  let apiPort: number;
  let apiUrl: string;
  
  // Sample patterns that would be served by the API
  const mockPatterns: SecurityPattern[] = [
    {
      id: 'sql-injection-001',
      name: 'SQL Injection via String Concatenation',
      pattern: /query\s*\(\s*['"`].*?\+.*?['"`]\s*\)/,
      severity: 'critical',
      language: 'javascript',
      category: 'injection',
      description: 'Detects SQL queries built with string concatenation',
      recommendation: 'Use parameterized queries or prepared statements',
      cwe: 'CWE-89',
      owasp: 'A03:2021',
      examples: {
        vulnerable: 'db.query("SELECT * FROM users WHERE id = " + userId)',
        secure: 'db.query("SELECT * FROM users WHERE id = ?", [userId])'
      }
    },
    {
      id: 'xss-001',
      name: 'Cross-Site Scripting via innerHTML',
      pattern: /\.innerHTML\s*=\s*[^'"`]+(?:\+|$)/,
      severity: 'high',
      language: 'javascript',
      category: 'xss',
      description: 'Detects potential XSS via innerHTML with dynamic content',
      recommendation: 'Use textContent or proper sanitization',
      cwe: 'CWE-79',
      owasp: 'A03:2021',
      examples: {
        vulnerable: 'element.innerHTML = userInput',
        secure: 'element.textContent = userInput'
      }
    },
    {
      id: 'hardcoded-secret-001',
      name: 'Hardcoded API Key',
      pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"`][a-zA-Z0-9]{20,}['"`]/i,
      severity: 'high',
      language: 'javascript',
      category: 'sensitive-data',
      description: 'Detects hardcoded API keys in source code',
      recommendation: 'Use environment variables or secure key management',
      cwe: 'CWE-798',
      owasp: 'A02:2021',
      examples: {
        vulnerable: 'const API_KEY = "sk_live_abcd1234567890"',
        secure: 'const API_KEY = process.env.API_KEY'
      }
    }
  ];

  beforeAll(async () => {
    // Create a mock API server
    await new Promise<void>((resolve) => {
      server = createServer((req, res) => {
        res.setHeader('Content-Type', 'application/json');
        
        if (req.url === '/patterns' && req.method === 'GET') {
          res.statusCode = 200;
          res.end(JSON.stringify({ patterns: mockPatterns }));
        } else if (req.url === '/patterns?language=javascript' && req.method === 'GET') {
          res.statusCode = 200;
          res.end(JSON.stringify({ 
            patterns: mockPatterns.filter(p => p.language === 'javascript') 
          }));
        } else if (req.url === '/patterns?category=injection' && req.method === 'GET') {
          res.statusCode = 200;
          res.end(JSON.stringify({ 
            patterns: mockPatterns.filter(p => p.category === 'injection') 
          }));
        } else if (req.url === '/health' && req.method === 'GET') {
          res.statusCode = 200;
          res.end(JSON.stringify({ status: 'healthy' }));
        } else {
          res.statusCode = 404;
          res.end(JSON.stringify({ error: 'Not found' }));
        }
      });
      
      server.listen(0, () => {
        const address = server.address();
        if (address && typeof address !== 'string') {
          apiPort = address.port;
          apiUrl = `http://localhost:${apiPort}`;
          resolve();
        }
      });
    });
  });

  afterAll(() => {
    server.close();
  });

  test('SecurityDetectorV2 fetches patterns from API and detects vulnerabilities', async () => {
    // Initialize detector with API client
    const apiClient = new PatternApiClient({
      baseUrl: apiUrl,
      apiKey: 'test-key'
    });
    
    const detector = new SecurityDetectorV2({
      apiClient,
      cacheEnabled: false // Disable cache for testing
    });

    // Code with multiple vulnerabilities
    const vulnerableCode = `
      // SQL Injection vulnerability
      function getUserData(userId) {
        const query = db.query("SELECT * FROM users WHERE id = " + userId);
        return query;
      }

      // XSS vulnerability
      function displayMessage(message) {
        document.getElementById('output').innerHTML = message;
      }

      // Hardcoded secret
      const API_KEY = "sk_live_1234567890abcdefghij";
      
      // Safe code
      function safeQuery(userId) {
        return db.query("SELECT * FROM users WHERE id = ?", [userId]);
      }
    `;

    const issues = await detector.detectIssues({
      content: vulnerableCode,
      filePath: 'test.js',
      language: 'javascript'
    });

    // Verify issues were detected
    expect(issues.length).toBe(3);

    // Verify SQL injection detection
    const sqlInjection = issues.find(i => i.patternId === 'sql-injection-001');
    expect(sqlInjection).toBeDefined();
    expect(sqlInjection?.severity).toBe('critical');
    expect(sqlInjection?.line).toBeGreaterThan(0);
    expect(sqlInjection?.column).toBeGreaterThan(0);
    expect(sqlInjection?.message).toContain('SQL Injection');

    // Verify XSS detection
    const xss = issues.find(i => i.patternId === 'xss-001');
    expect(xss).toBeDefined();
    expect(xss?.severity).toBe('high');
    expect(xss?.message).toContain('Cross-Site Scripting');

    // Verify hardcoded secret detection
    const secret = issues.find(i => i.patternId === 'hardcoded-secret-001');
    expect(secret).toBeDefined();
    expect(secret?.severity).toBe('high');
    expect(secret?.message).toContain('Hardcoded API Key');
  });

  test('SecurityDetectorV2 filters patterns by language', async () => {
    const apiClient = new PatternApiClient({
      baseUrl: apiUrl,
      apiKey: 'test-key'
    });
    
    const detector = new SecurityDetectorV2({
      apiClient,
      cacheEnabled: false
    });

    // Python code (should not match JavaScript patterns)
    const pythonCode = `
      # This looks like SQL injection but is Python
      query = f"SELECT * FROM users WHERE id = {user_id}"
    `;

    const issues = await detector.detectIssues({
      content: pythonCode,
      filePath: 'test.py',
      language: 'python'
    });

    // Should not detect issues since patterns are for JavaScript
    expect(issues.length).toBe(0);
  });

  test('SecurityDetectorV2 handles API errors gracefully', async () => {
    // Use a non-existent endpoint to trigger error
    const apiClient = new PatternApiClient({
      baseUrl: `http://localhost:${apiPort + 1}`, // Wrong port
      apiKey: 'test-key'
    });
    
    const detector = new SecurityDetectorV2({
      apiClient,
      cacheEnabled: false,
      fallbackPatterns: [mockPatterns[0]] // Provide fallback
    });

    const vulnerableCode = `
      const query = db.query("SELECT * FROM users WHERE id = " + userId);
    `;

    // Should fall back to local patterns
    const issues = await detector.detectIssues({
      content: vulnerableCode,
      filePath: 'test.js',
      language: 'javascript'
    });

    // Should still detect the SQL injection using fallback patterns
    expect(issues.length).toBe(1);
    expect(issues[0].patternId).toBe('sql-injection-001');
  });

  test('SecurityDetectorV2 respects severity filtering', async () => {
    const apiClient = new PatternApiClient({
      baseUrl: apiUrl,
      apiKey: 'test-key'
    });
    
    const detector = new SecurityDetectorV2({
      apiClient,
      cacheEnabled: false,
      minSeverity: 'critical' // Only detect critical issues
    });

    const mixedCode = `
      // Critical: SQL Injection
      db.query("SELECT * FROM users WHERE id = " + userId);
      
      // High: XSS (should be filtered out)
      element.innerHTML = userInput;
    `;

    const issues = await detector.detectIssues({
      content: mixedCode,
      filePath: 'test.js',
      language: 'javascript'
    });

    // Should only detect critical issues
    expect(issues.length).toBe(1);
    expect(issues[0].severity).toBe('critical');
    expect(issues[0].patternId).toBe('sql-injection-001');
  });

  test('SecurityDetectorV2 provides detailed issue context', async () => {
    const apiClient = new PatternApiClient({
      baseUrl: apiUrl,
      apiKey: 'test-key'
    });
    
    const detector = new SecurityDetectorV2({
      apiClient,
      cacheEnabled: false
    });

    const codeWithContext = `
      function processUserInput(userId) {
        // This is vulnerable to SQL injection
        const query = db.query("SELECT * FROM users WHERE id = " + userId);
        return query.results;
      }
    `;

    const issues = await detector.detectIssues({
      content: codeWithContext,
      filePath: 'user-service.js',
      language: 'javascript'
    });

    expect(issues.length).toBe(1);
    
    const issue = issues[0];
    
    // Verify issue has complete context
    expect(issue.filePath).toBe('user-service.js');
    expect(issue.line).toBe(4); // Line with the vulnerability
    expect(issue.column).toBeGreaterThan(0);
    expect(issue.snippet).toContain('db.query');
    expect(issue.recommendation).toContain('parameterized queries');
    expect(issue.cwe).toBe('CWE-89');
    expect(issue.owasp).toBe('A03:2021');
    expect(issue.examples).toBeDefined();
    expect(issue.examples?.vulnerable).toContain('db.query');
    expect(issue.examples?.secure).toContain('?');
  });

  test('SecurityDetectorV2 batches multiple file scans efficiently', async () => {
    const apiClient = new PatternApiClient({
      baseUrl: apiUrl,
      apiKey: 'test-key'
    });
    
    const detector = new SecurityDetectorV2({
      apiClient,
      cacheEnabled: true // Enable cache for batch efficiency
    });

    const files = [
      {
        content: 'db.query("SELECT * FROM users WHERE id = " + id)',
        filePath: 'file1.js',
        language: 'javascript' as const
      },
      {
        content: 'element.innerHTML = userInput',
        filePath: 'file2.js',
        language: 'javascript' as const
      },
      {
        content: 'const API_KEY = "sk_live_secret123456789012"',
        filePath: 'file3.js',
        language: 'javascript' as const
      }
    ];

    // Scan all files
    const allIssues: SecurityIssue[] = [];
    
    for (const file of files) {
      const issues = await detector.detectIssues(file);
      allIssues.push(...issues);
    }

    // Verify all vulnerabilities detected
    expect(allIssues.length).toBe(3);
    
    // Verify each file has correct issue
    expect(allIssues.find(i => i.filePath === 'file1.js')?.patternId).toBe('sql-injection-001');
    expect(allIssues.find(i => i.filePath === 'file2.js')?.patternId).toBe('xss-001');
    expect(allIssues.find(i => i.filePath === 'file3.js')?.patternId).toBe('hardcoded-secret-001');
  });

  test('Pattern API health check works', async () => {
    const apiClient = new PatternApiClient({
      baseUrl: apiUrl,
      apiKey: 'test-key'
    });

    const health = await apiClient.checkHealth();
    expect(health.status).toBe('healthy');
  });
});