import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ValidationEnricher } from '../enricher.js';
import { IssueContext } from '../../types/index.js';

describe('ValidationEnricher', () => {
  let enricher: ValidationEnricher;
  
  beforeEach(() => {
    vi.clearAllMocks();
    enricher = new ValidationEnricher('github-token', 'rsolv-api-key');
  });

  describe('parseIssueForFiles', () => {
    it('should detect file paths in backticks', () => {
      const issue: IssueContext = {
        id: 'test-1',
        number: 1,
        title: 'Test Issue',
        body: 'There is a bug in `app/routes/profile.js` that needs fixing.',
        labels: [],
        repository: {
          owner: 'test',
          name: 'repo',
          fullName: 'test/repo'
        }
      };

      // Access private method via reflection for testing
      const files = (enricher as any).parseIssueForFiles(issue);
      
      expect(files).toContain('app/routes/profile.js');
    });

    it('should detect file paths in Affected Files section', () => {
      const issue: IssueContext = {
        id: 'test-2',
        number: 2,
        title: 'Test Issue',
        body: '**Affected Files**:\n- app/routes/profile.js\n- lib/db.js',
        labels: [],
        repository: {
          owner: 'test',
          name: 'repo',
          fullName: 'test/repo'
        }
      };

      const files = (enricher as any).parseIssueForFiles(issue);
      
      expect(files).toContain('app/routes/profile.js');
      expect(files).toContain('lib/db.js');
    });

    it('should detect file paths with File: prefix in code blocks', () => {
      const issue: IssueContext = {
        id: 'test-3',
        number: 3,
        title: 'Test Issue',
        body: '```javascript\n// File: app/routes/profile.js\nconst code = "test";\n```',
        labels: [],
        repository: {
          owner: 'test',
          name: 'repo',
          fullName: 'test/repo'
        }
      };

      const files = (enricher as any).parseIssueForFiles(issue);
      
      expect(files).toContain('app/routes/profile.js');
    });

    // RED TEST - This should fail initially
    it('should detect file paths in plain comments within code blocks', () => {
      const issue: IssueContext = {
        id: 'test-4',
        number: 4,
        title: 'SQL Injection vulnerability',
        body: 'There is a SQL injection vulnerability:\n\n```javascript\n// app/routes/profile.js\nconst query = "SELECT * FROM users WHERE id = \'" + req.params.id + "\'";\n```',
        labels: [],
        repository: {
          owner: 'test',
          name: 'repo',
          fullName: 'test/repo'
        }
      };

      const files = (enricher as any).parseIssueForFiles(issue);
      
      expect(files).toContain('app/routes/profile.js');
    });

    // Additional RED TEST - Should detect multiple file formats
    it('should detect various file path comment formats', () => {
      const issue: IssueContext = {
        id: 'test-5',
        number: 5,
        title: 'Multiple vulnerabilities',
        body: '```javascript\n// app/routes/profile.js\ncode1();\n```\n\n```python\n# lib/auth.py\ncode2()\n```\n\n```ruby\n# app/models/user.rb\ncode3\n```',
        labels: [],
        repository: {
          owner: 'test',
          name: 'repo',
          fullName: 'test/repo'
        }
      };

      const files = (enricher as any).parseIssueForFiles(issue);
      
      expect(files).toContain('app/routes/profile.js');
      expect(files).toContain('lib/auth.py');
      expect(files).toContain('app/models/user.rb');
    });
  });

  describe('analyzeFile', () => {
    beforeEach(() => {
      // Mock file system
      vi.mock('fs', () => ({
        existsSync: vi.fn(() => true),
        readFileSync: vi.fn()
      }));
    });

    it('should detect SQL injection vulnerability in file content', async () => {
      const fs = await import('fs');
      vi.mocked(fs.readFileSync).mockReturnValue(
        'const query = "SELECT * FROM users WHERE id = \'" + req.params.id + "\'";\ndb.query(query);'
      );

      const issue: IssueContext = {
        id: 'test-sql',
        number: 100,
        title: 'SQL Injection vulnerability',
        body: 'SQL injection found',
        labels: [],
        repository: {
          owner: 'test',
          name: 'repo',
          fullName: 'test/repo'
        }
      };

      const vulnerabilities = await (enricher as any).analyzeFile('app/routes/profile.js', issue);
      
      expect(vulnerabilities).toHaveLength(1);
      expect(vulnerabilities[0]).toMatchObject({
        file: 'app/routes/profile.js',
        pattern: 'String concatenation in SQL query',
        cweId: 'CWE-89',
        owasp: 'A03:2021'
      });
    });

    it('should detect XSS vulnerability in file content', async () => {
      const fs = await import('fs');
      vi.mocked(fs.readFileSync).mockReturnValue(
        'element.innerHTML = req.query.userInput;'
      );

      const issue: IssueContext = {
        id: 'test-xss',
        number: 101,
        title: 'Cross-Site Scripting (XSS) vulnerability',
        body: 'XSS found',
        labels: [],
        repository: {
          owner: 'test',
          name: 'repo',
          fullName: 'test/repo'
        }
      };

      const vulnerabilities = await (enricher as any).analyzeFile('app/views/render.js', issue);
      
      expect(vulnerabilities.length).toBeGreaterThan(0);
      expect(vulnerabilities[0]).toMatchObject({
        file: 'app/views/render.js',
        pattern: 'Direct HTML injection',
        cweId: 'CWE-79'
      });
    });
  });

  describe('AST Validation', () => {
    beforeEach(() => {
      // Mock fetch globally
      global.fetch = vi.fn();
    });

    it('should call AST validation API with correct parameters when API key is provided', async () => {
      const mockFetch = global.fetch as any;
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          validated: [
            {
              id: 'temp-123',
              isValid: true,
              confidence: 0.95,
              astContext: {
                inUserInputFlow: true,
                hasValidation: false
              }
            }
          ],
          stats: {
            total: 1,
            validated: 1,
            rejected: 0
          }
        })
      });

      const fs = await import('fs');
      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(
        'const preTax = eval(req.body.preTax);'
      );

      const issue: IssueContext = {
        id: 'test-eval',
        number: 216,
        title: 'Server-Side JavaScript Injection via eval()',
        body: 'app/routes/contributions.js\n- **Lines 60-63**: Direct use of eval() on user input',
        labels: ['security', 'rsolv:detected'],
        repository: {
          owner: 'test',
          name: 'repo',
          fullName: 'test/repo'
        }
      };

      // Test private method through analyzeFile which calls runASTValidation
      const vulnerabilities = await (enricher as any).analyzeFile('app/routes/contributions.js', issue);

      // Verify AST validation was called
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/vulnerabilities/validate'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'x-api-key': 'rsolv-api-key',
            'Content-Type': 'application/json'
          }),
          body: expect.stringContaining('contributions.js')
        })
      );

      // Verify AST results are used
      expect(vulnerabilities).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            astValidation: true
          })
        ])
      );
    });

    it('should handle AST validation API failures gracefully', async () => {
      const mockFetch = global.fetch as any;
      mockFetch.mockResolvedValueOnce({
        ok: false,
        statusText: 'Not Found'
      });

      const fs = await import('fs');
      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(
        'const preTax = eval(req.body.preTax);'
      );

      const issue: IssueContext = {
        id: 'test-eval-fail',
        number: 217,
        title: 'Server-Side JavaScript Injection via eval()',
        body: 'app/routes/contributions.js',
        labels: ['security'],
        repository: {
          owner: 'test',
          name: 'repo',
          fullName: 'test/repo'
        }
      };

      // Should still return vulnerabilities even if AST fails
      const vulnerabilities = await (enricher as any).analyzeFile('app/routes/contributions.js', issue);
      
      expect(mockFetch).toHaveBeenCalled();
      // Should still detect via regex patterns
      expect(vulnerabilities.length).toBeGreaterThan(0);
    });

    it('should not call AST validation when no API key is provided', async () => {
      // Create enricher without API key
      const enricherNoKey = new ValidationEnricher('github-token', undefined);
      const mockFetch = global.fetch as any;
      mockFetch.mockClear();

      const fs = await import('fs');
      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(
        'const preTax = eval(req.body.preTax);'
      );

      const issue: IssueContext = {
        id: 'test-no-key',
        number: 218,
        title: 'JavaScript Injection',
        body: 'app/routes/contributions.js',
        labels: ['security'],
        repository: {
          owner: 'test',
          name: 'repo',
          fullName: 'test/repo'
        }
      };

      await (enricherNoKey as any).analyzeFile('app/routes/contributions.js', issue);

      // Should not call AST validation without API key
      expect(mockFetch).not.toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/vulnerabilities/validate'),
        expect.anything()
      );
    });
  });

  describe('extractVulnerabilityType', () => {
    it('should detect SQL injection from issue title', () => {
      const issue: IssueContext = {
        id: 'test-6',
        number: 6,
        title: 'SQL Injection in app/routes/profile.js',
        body: 'SQL injection vulnerability found',
        labels: [],
        repository: {
          owner: 'test',
          name: 'repo',
          fullName: 'test/repo'
        }
      };

      const vulnType = (enricher as any).extractVulnerabilityType(issue);
      
      expect(vulnType).toBe('sql-injection');
    });

    it('should detect XSS from issue title', () => {
      const issue: IssueContext = {
        id: 'test-7',
        number: 7,
        title: 'Cross-Site Scripting (XSS) vulnerability',
        body: 'XSS vulnerability found',
        labels: [],
        repository: {
          owner: 'test',
          name: 'repo',
          fullName: 'test/repo'
        }
      };

      const vulnType = (enricher as any).extractVulnerabilityType(issue);
      
      expect(vulnType).toBe('xss');
    });
  });
});