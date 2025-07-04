import { describe, it, expect, beforeEach, jest } from 'bun:test';
import { SecurityDetectorV2 } from '../src/security/detector-v2';
import { ElixirASTAnalyzer } from '../src/security/analyzers/elixir-ast-analyzer';
import { SecurityPattern } from '../src/types';

describe('Server-Side AST Integration', () => {
  let detector: SecurityDetectorV2;

  beforeEach(() => {
    // This will need to be configured with staging API for testing
    process.env.RSOLV_API_URL = 'https://api.rsolv-staging.com';
    process.env.RSOLV_API_KEY = 'test_key';
  });

  describe('RED Phase - These tests should FAIL initially', () => {
    it('should use ElixirASTAnalyzer for vulnerability detection', () => {
      // This should FAIL because detector currently uses ASTPatternInterpreter
      detector = new SecurityDetectorV2();
      
      // We expect the detector to have an astInterpreter property that's an ElixirASTAnalyzer
      // Currently it has ASTPatternInterpreter which is wrong
      expect(detector).toHaveProperty('astInterpreter');
      expect((detector as any).astInterpreter).toBeInstanceOf(ElixirASTAnalyzer);
    });

    it('should detect Python SQL injection via server AST', async () => {
      // This should FAIL because only JS/TS supported locally
      detector = new SecurityDetectorV2();
      const pythonCode = `
import mysql.connector

def get_user(user_id):
    conn = mysql.connector.connect(host='localhost', user='root', password='pass')
    cursor = conn.cursor()
    
    # Vulnerable: String concatenation in SQL
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    
    return cursor.fetchall()
      `.trim();

      const results = await detector.detect(pythonCode, 'python', 'vulnerable.py');
      
      // Should detect SQL injection
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].type).toBe('sql-injection');
      expect(results[0].severity).toBe('critical');
    });

    it('should detect Ruby command injection via server AST', async () => {
      // This should FAIL because Ruby not supported locally
      detector = new SecurityDetectorV2();
      const rubyCode = `
class FileProcessor
  def process_file(filename)
    # Vulnerable: Direct command execution with user input
    result = \`cat #{filename}\`
    
    return result
  end
end
      `.trim();

      const results = await detector.detect(rubyCode, 'ruby', 'processor.rb');
      
      // Should detect command injection
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].type).toBe('command-injection');
    });

    it('should detect PHP XSS via server AST', async () => {
      // This should FAIL because PHP not supported locally
      detector = new SecurityDetectorV2();
      const phpCode = `
<?php
function displayUser($username) {
    // Vulnerable: Direct echo of user input
    echo "<h1>Welcome " . $username . "</h1>";
}

// Called with user input
displayUser($_GET['name']);
?>
      `.trim();

      const results = await detector.detect(phpCode, 'php', 'display.php');
      
      // Should detect XSS
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].type).toBe('xss');
    });

    it('should achieve >90% accuracy on mixed language corpus', async () => {
      // This should FAIL with current 57.1% accuracy
      detector = new SecurityDetectorV2();
      const testFiles = [
        { code: 'eval(userInput)', lang: 'js', hasVuln: true },
        { code: 'eval("safe string")', lang: 'js', hasVuln: false },
        { code: 'cursor.execute("SELECT * FROM users WHERE id = " + id)', lang: 'python', hasVuln: true },
        { code: 'cursor.execute("SELECT * FROM users WHERE id = ?", [id])', lang: 'python', hasVuln: false },
        { code: 'system("ls " + params[:dir])', lang: 'ruby', hasVuln: true },
        { code: 'echo $_GET["name"];', lang: 'php', hasVuln: true },
        { code: 'db.Query("SELECT * FROM users WHERE id = " + id)', lang: 'go', hasVuln: true },
      ];

      let correct = 0;
      let total = testFiles.length;

      for (const testFile of testFiles) {
        const results = await detector.detect(
          testFile.code, 
          testFile.lang,
          `test.${testFile.lang}`
        );
        
        const foundVuln = results.length > 0;
        if (foundVuln === testFile.hasVuln) {
          correct++;
        }
      }

      const accuracy = correct / total;
      expect(accuracy).toBeGreaterThan(0.9); // Expect >90% accuracy
    });

    it('should use server-side AST service endpoint', async () => {
      // This should FAIL if not calling the AST service
      const mockApiCall = jest.fn();
      
      // Spy on API calls to verify it's calling the AST endpoint
      const detector = new SecurityDetectorV2({ 
        apiClient: { 
          post: mockApiCall 
        } 
      });

      await detector.detect('eval(x)', 'javascript', 'test.js');
      
      // Should have called the AST analyze endpoint
      expect(mockApiCall).toHaveBeenCalledWith(
        '/api/v1/ast/analyze',
        expect.any(Object)
      );
    });
  });

  describe('Test Infrastructure', () => {
    it('should have ElixirASTAnalyzer class available', () => {
      // This should PASS - we know the class exists
      expect(ElixirASTAnalyzer).toBeDefined();
      
      const analyzer = new ElixirASTAnalyzer({
        apiUrl: 'https://api.rsolv-staging.com',
        apiKey: 'test'
      });
      
      expect(analyzer).toHaveProperty('analyzeFile');
      expect(analyzer).toHaveProperty('analyzeFiles');
    });
  });
});