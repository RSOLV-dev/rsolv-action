/**
 * Test suite for ValidationMode fallback strategies
 * RFC-060-AMENDMENT-001 Phase 2: Graceful degradation and fallback
 *
 * Tests all 4 fallback scenarios:
 * 1. Backend unreachable
 * 2. Analyze API failure
 * 3. Generate API (AST) failure
 * 4. Framework detection failure
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ValidationMode } from '../validation-mode.js';
import { IssueContext, ActionConfig } from '../../types/index.js';
import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

// Mock dependencies
vi.mock('../../github/api.js', () => ({
  getGitHubClient: vi.fn(() => ({
    issues: {
      addLabels: vi.fn()
    }
  }))
}));

vi.mock('../../ai/analyzer');
vi.mock('../../ai/test-generating-security-analyzer');
vi.mock('../../ai/git-based-test-validator');
vi.mock('child_process');
vi.mock('fs');

describe('ValidationMode - Fallback Strategies', () => {
  let validationMode: ValidationMode;
  let testRepoPath: string;
  let mockConfig: ActionConfig;

  beforeEach(() => {
    // Setup test path
    testRepoPath = '/test-repo-fallback';

    // Mock config
    mockConfig = {
      aiProvider: {
        provider: 'anthropic',
        apiKey: 'test-key',
        model: 'claude-3-5-sonnet-20241022',
        maxTokens: 4000,
        useVendedCredentials: false
      },
      githubToken: 'test-github-token',
      mode: 'validate',
      executableTests: true
    };

    validationMode = new ValidationMode(mockConfig, testRepoPath);

    // Mock file system operations
    (fs.existsSync as any).mockReturnValue(true);
    (fs.readFileSync as any).mockReturnValue('{}');
    (fs.writeFileSync as any).mockImplementation(() => {});
    (fs.mkdirSync as any).mockImplementation(() => {});
    (fs.readdirSync as any).mockReturnValue([]);

    // Mock git operations
    (execSync as any).mockImplementation((cmd: string) => {
      if (cmd.includes('git status')) return 'nothing to commit, working tree clean';
      if (cmd.includes('git rev-parse HEAD')) return 'abc123def456';
      if (cmd.includes('git checkout -b')) return '';
      if (cmd.includes('git add')) return '';
      if (cmd.includes('git commit')) return '';
      if (cmd.includes('git push')) return '';
      if (cmd.includes('git config')) return '';
      return '';
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('Scenario 1: Backend unreachable', () => {
    it('should fall back to local framework detection when backend is unavailable', async () => {
      // Arrange: Create a package.json with vitest
      const packageJson = {
        name: 'test-app',
        devDependencies: {
          vitest: '^1.0.0'
        }
      };
      fs.writeFileSync(
        path.join(testRepoPath, 'package.json'),
        JSON.stringify(packageJson, null, 2)
      );

      // Create test directory structure
      const testDir = path.join(testRepoPath, '__tests__');
      fs.mkdirSync(testDir, { recursive: true });
      fs.writeFileSync(path.join(testDir, 'example.test.ts'), '// Existing test');

      // Commit changes
      execSync('git add .', { cwd: testRepoPath, stdio: 'pipe' });
      execSync('git commit -m "Add package.json"', { cwd: testRepoPath, stdio: 'pipe' });

      // Create validation branch
      const branchName = 'rsolv/validate/issue-123';
      execSync(`git checkout -b ${branchName}`, { cwd: testRepoPath, stdio: 'pipe' });

      // Mock issue with vulnerable file
      const issue: IssueContext = {
        number: 123,
        title: 'SQL Injection vulnerability',
        body: 'Vulnerability in user controller',
        file: 'src/controllers/users.ts',
        repository: {
          owner: 'test-org',
          name: 'test-repo',
          fullName: 'test-org/test-repo'
        }
      };

      // Create vulnerable file
      const srcDir = path.join(testRepoPath, 'src', 'controllers');
      fs.mkdirSync(srcDir, { recursive: true });
      fs.writeFileSync(
        path.join(srcDir, 'users.ts'),
        'export class UsersController {}'
      );

      // Mock test content (RED test)
      const testContent = `
describe('UsersController - SQL Injection', () => {
  it('should reject SQL injection in user query', () => {
    const payload = "1' OR '1'='1";
    const result = controller.findUser(payload);
    expect(result).toBe(null); // Should reject
  });
});`;

      // Act: Commit tests with fallback
      await validationMode.commitTestsToBranch(testContent, branchName, issue);

      // Assert: Test file should be created in framework directory
      const expectedTestFile = path.join(testRepoPath, '__tests__', 'src', 'controllers', 'users.security.test.ts');
      const testFileExists = fs.existsSync(expectedTestFile);

      expect(testFileExists).toBe(true);

      if (testFileExists) {
        const content = fs.readFileSync(expectedTestFile, 'utf8');
        expect(content).toContain('RSOLV Security Test');
        expect(content).toContain('UsersController - SQL Injection');
      }

      // Verify commit message indicates fallback
      const lastCommit = execSync('git log -1 --pretty=%B', {
        cwd: testRepoPath,
        encoding: 'utf8'
      }).trim();
      expect(lastCommit).toContain('fallback mode');
    });
  });

  describe('Scenario 2: Analyze API failure (local heuristics)', () => {
    it('should select test file using local heuristics when analyze API fails', async () => {
      // Arrange: Create RSpec project structure
      const gemfile = `
source 'https://rubygems.org'
gem 'rspec'
gem 'rails'
`;
      fs.writeFileSync(path.join(testRepoPath, 'Gemfile'), gemfile);

      // Create spec directory with existing tests
      const specDir = path.join(testRepoPath, 'spec', 'controllers');
      fs.mkdirSync(specDir, { recursive: true });

      // Create existing test files
      fs.writeFileSync(
        path.join(specDir, 'users_controller_spec.rb'),
        'RSpec.describe UsersController do\nend'
      );
      fs.writeFileSync(
        path.join(specDir, 'posts_controller_spec.rb'),
        'RSpec.describe PostsController do\nend'
      );

      // Create vulnerable file in app/controllers
      const controllersDir = path.join(testRepoPath, 'app', 'controllers');
      fs.mkdirSync(controllersDir, { recursive: true });
      fs.writeFileSync(
        path.join(controllersDir, 'users_controller.rb'),
        'class UsersController < ApplicationController\nend'
      );

      // Commit changes
      execSync('git add .', { cwd: testRepoPath, stdio: 'pipe' });
      execSync('git commit -m "Add Rails structure"', { cwd: testRepoPath, stdio: 'pipe' });

      // Create validation branch
      const branchName = 'rsolv/validate/issue-456';
      execSync(`git checkout -b ${branchName}`, { cwd: testRepoPath, stdio: 'pipe' });

      // Mock issue
      const issue: IssueContext = {
        number: 456,
        title: 'SQL Injection in UsersController',
        body: 'String interpolation in WHERE clause',
        file: 'app/controllers/users_controller.rb',
        repository: {
          owner: 'test-org',
          name: 'railsgoat',
          fullName: 'test-org/railsgoat'
        }
      };

      // RED test based on REALISTIC-VULNERABILITY-EXAMPLES.md
      const testContent = `
# Based on RailsGoat vulnerability: String interpolation in WHERE clause
# Vulnerable pattern: User.where("id = '#{params[:user][:id]}'")
it 'should reject SQL injection in user update' do
  post '/users/update', params: {
    user: {
      id: "5') OR admin = 't' --'",  # SQL injection payload
      name: 'attacker'
    }
  }

  # Test expectations (FAILS on vulnerable code):
  expect(response.status).to eq(400)  # Should reject malicious input
  expect(User.find(5).admin).to be_falsey  # Should not escalate to admin
end`;

      // Act: Commit tests with fallback
      await validationMode.commitTestsToBranch(testContent, branchName, issue);

      // Assert: Test should be appended to users_controller_spec.rb (local heuristic match)
      const targetFile = path.join(specDir, 'users_controller_spec.rb');
      const content = fs.readFileSync(targetFile, 'utf8');

      expect(content).toContain('RSOLV Security Test');
      expect(content).toContain('SQL injection');
      expect(content).toContain("5') OR admin = 't' --'");
      expect(content).toContain('RailsGoat vulnerability');
    });
  });

  describe('Scenario 3: Generate API (AST) failure (simple append)', () => {
    it('should append test with proper formatting when AST integration fails', async () => {
      // Arrange: Create pytest project
      const requirementsTxt = 'pytest==7.4.0\npytest-cov==4.1.0';
      fs.writeFileSync(path.join(testRepoPath, 'requirements.txt'), requirementsTxt);

      // Create test directory
      const testDir = path.join(testRepoPath, 'tests');
      fs.mkdirSync(testDir, { recursive: true });

      // Create existing test file
      const existingTest = `
import pytest

def test_existing():
    assert True
`;
      fs.writeFileSync(path.join(testDir, 'test_users.py'), existingTest);

      // Create vulnerable file
      const srcDir = path.join(testRepoPath, 'src');
      fs.mkdirSync(srcDir, { recursive: true });
      fs.writeFileSync(
        path.join(srcDir, 'users.py'),
        'def get_user(user_id):\n    pass'
      );

      // Commit changes
      execSync('git add .', { cwd: testRepoPath, stdio: 'pipe' });
      execSync('git commit -m "Add pytest structure"', { cwd: testRepoPath, stdio: 'pipe' });

      // Create validation branch
      const branchName = 'rsolv/validate/issue-789';
      execSync(`git checkout -b ${branchName}`, { cwd: testRepoPath, stdio: 'pipe' });

      // Mock issue
      const issue: IssueContext = {
        number: 789,
        title: 'NoSQL Injection',
        body: 'MongoDB operator injection in user authentication',
        file: 'src/users.py',
        repository: {
          owner: 'test-org',
          name: 'nodegoat',
          fullName: 'test-org/nodegoat'
        }
      };

      // RED test based on REALISTIC-VULNERABILITY-EXAMPLES.md
      const testContent = `
# Based on NodeGoat vulnerability: MongoDB operator injection
# Vulnerable pattern: db.accounts.find({username: username, password: password})
def test_nosql_injection_rejection():
    """Should reject NoSQL injection in authentication"""
    # Attack vector from NodeGoat
    payload = {"$gt": ""}  # MongoDB operator injection

    result = authenticate_user("admin", payload)

    # Test FAILS on vulnerable code (allows bypass)
    assert result is None, "Should reject MongoDB operator injection"
`;

      // Act: Commit tests with fallback (AST would fail, append instead)
      await validationMode.commitTestsToBranch(testContent, branchName, issue);

      // Assert: Test should be appended with proper Python formatting
      const targetFile = path.join(testDir, 'test_users.py');
      const content = fs.readFileSync(targetFile, 'utf8');

      expect(content).toContain('test_existing');  // Original test preserved
      expect(content).toContain('RSOLV Security Test');
      expect(content).toContain('test_nosql_injection_rejection');
      expect(content).toContain('MongoDB operator injection');
      expect(content).toContain('NodeGoat vulnerability');

      // Verify proper Python formatting (no tabs, proper indentation)
      expect(content).toMatch(/def test_security_validation\(\):/);
    });
  });

  describe('Scenario 4: Framework detection failure (ultimate fallback)', () => {
    it('should use .rsolv/tests/ directory when framework detection fails', async () => {
      // Arrange: Create repo with NO recognizable test framework
      const readmePath = path.join(testRepoPath, 'README.md');
      fs.writeFileSync(readmePath, '# App with no test framework');

      // Commit changes
      execSync('git add .', { cwd: testRepoPath, stdio: 'pipe' });
      execSync('git commit -m "Add README"', { cwd: testRepoPath, stdio: 'pipe' });

      // Create validation branch
      const branchName = 'rsolv/validate/issue-999';
      execSync(`git checkout -b ${branchName}`, { cwd: testRepoPath, stdio: 'pipe' });

      // Mock issue
      const issue: IssueContext = {
        number: 999,
        title: 'XSS Vulnerability',
        body: 'Stored XSS in user profile',
        file: 'app.js',
        repository: {
          owner: 'test-org',
          name: 'vulnerable-app',
          fullName: 'test-org/vulnerable-app'
        }
      };

      // RED test based on REALISTIC-VULNERABILITY-EXAMPLES.md
      const testContent = `
// Based on NodeGoat vulnerability: Unescaped output
// Vulnerable pattern: res.send(\`<p>Bio: \${user.bio}</p>\`)
it('should escape XSS in profile bio', async () => {
  const xssPayload = '<script>alert("XSS")</script>';

  // Create user with XSS payload
  await User.create({
    name: 'attacker',
    bio: xssPayload
  });

  const response = await request(app).get('/profile/attacker');

  // Test FAILS on vulnerable code (renders script)
  expect(response.text).not.toContain('<script>');  // Should be escaped
  expect(response.text).toContain('&lt;script&gt;');  // Should see encoded version
});`;

      // Act: Commit tests with ultimate fallback
      await validationMode.commitTestsToBranch(testContent, branchName, issue);

      // Assert: Test should be in .rsolv/tests/ directory
      const fallbackDir = path.join(testRepoPath, '.rsolv', 'tests');
      const fallbackFile = path.join(fallbackDir, 'validation.test.js');

      expect(fs.existsSync(fallbackFile)).toBe(true);

      const content = fs.readFileSync(fallbackFile, 'utf8');
      expect(content).toContain('XSS');
      expect(content).toContain('NodeGoat vulnerability');
      expect(content).toContain('<script>alert("XSS")</script>');

      // Verify commit message indicates fallback
      const lastCommit = execSync('git log -1 --pretty=%B', {
        cwd: testRepoPath,
        encoding: 'utf8'
      }).trim();
      expect(lastCommit).toContain('fallback mode');
    });
  });

  describe('Telemetry logging', () => {
    it('should log telemetry for each fallback scenario', async () => {
      // This test verifies that telemetry is logged correctly
      // In production, this would be sent to a metrics backend

      const logSpy = vi.spyOn(console, 'log');

      // Arrange: Create repo with vitest
      const packageJson = {
        name: 'telemetry-test',
        devDependencies: { vitest: '^1.0.0' }
      };
      fs.writeFileSync(
        path.join(testRepoPath, 'package.json'),
        JSON.stringify(packageJson, null, 2)
      );

      execSync('git add .', { cwd: testRepoPath, stdio: 'pipe' });
      execSync('git commit -m "Add package.json"', { cwd: testRepoPath, stdio: 'pipe' });

      const branchName = 'rsolv/validate/issue-telemetry';
      execSync(`git checkout -b ${branchName}`, { cwd: testRepoPath, stdio: 'pipe' });

      const issue: IssueContext = {
        number: 1234,
        title: 'Test telemetry',
        body: 'Testing telemetry logging',
        file: 'src/app.ts',
        repository: {
          owner: 'test-org',
          name: 'test-app',
          fullName: 'test-org/test-app'
        }
      };

      // Act
      await validationMode.commitTestsToBranch('test content', branchName, issue);

      // Assert: Verify telemetry events were logged
      const logs = logSpy.mock.calls.map(call => call.join(' ')).join('\n');

      expect(logs).toContain('FALLBACK TELEMETRY');
      expect(logs).toContain('backend_unreachable');
      expect(logs).toContain('test_integration_fallback');

      logSpy.mockRestore();
    });
  });

  describe('Semantic file naming', () => {
    it('should generate framework-appropriate file names', async () => {
      // Test RSpec naming
      const gemfile = "gem 'rspec'";
      fs.writeFileSync(path.join(testRepoPath, 'Gemfile'), gemfile);

      const specDir = path.join(testRepoPath, 'spec');
      fs.mkdirSync(specDir, { recursive: true });

      execSync('git add .', { cwd: testRepoPath, stdio: 'pipe' });
      execSync('git commit -m "Add Gemfile"', { cwd: testRepoPath, stdio: 'pipe' });

      const branchName = 'rsolv/validate/issue-semantic';
      execSync(`git checkout -b ${branchName}`, { cwd: testRepoPath, stdio: 'pipe' });

      const issue: IssueContext = {
        number: 5678,
        title: 'Command Injection',
        body: 'OS command injection in backup function',
        file: 'app/services/backup_service.rb',
        repository: {
          owner: 'test-org',
          name: 'test-app',
          fullName: 'test-org/test-app'
        }
      };

      // Create the vulnerable file
      const servicesDir = path.join(testRepoPath, 'app', 'services');
      fs.mkdirSync(servicesDir, { recursive: true });
      fs.writeFileSync(
        path.join(servicesDir, 'backup_service.rb'),
        'class BackupService\nend'
      );

      // RED test based on REALISTIC-VULNERABILITY-EXAMPLES.md
      const testContent = `
# Based on real-world pattern: Command injection
# Vulnerable pattern: exec("tar -czf backup.tar.gz #{filename}")
it 'should reject command injection in backup' do
  response = post '/backup', filename: 'data.txt; rm -rf / #'

  # Test FAILS on vulnerable code (executes command)
  expect(response.status).to eq(400)  # Should reject
  expect(File.exist?('/tmp/test-file')).to be true  # System should be intact
end`;

      // Act
      await validationMode.commitTestsToBranch(testContent, branchName, issue);

      // Assert: File should follow RSpec naming convention
      // Expected: spec/app/services/backup_service_security_spec.rb
      const expectedPath = path.join(
        testRepoPath,
        'spec',
        'app',
        'services',
        'backup_service_security_spec.rb'
      );

      expect(fs.existsSync(expectedPath)).toBe(true);

      const content = fs.readFileSync(expectedPath, 'utf8');
      expect(content).toContain('Command injection');
      expect(content).toContain('data.txt; rm -rf / #');
    });
  });

  describe('Integration with realistic vulnerability patterns', () => {
    it('should maintain realistic attack vectors from REALISTIC-VULNERABILITY-EXAMPLES.md', async () => {
      // This test ensures fallback doesn't corrupt realistic vulnerability patterns

      // Arrange: Create Node.js project with Jest
      const packageJson = {
        name: 'realistic-vuln-test',
        devDependencies: { jest: '^29.0.0' }
      };
      fs.writeFileSync(
        path.join(testRepoPath, 'package.json'),
        JSON.stringify(packageJson, null, 2)
      );

      const testDir = path.join(testRepoPath, '__tests__');
      fs.mkdirSync(testDir, { recursive: true });

      execSync('git add .', { cwd: testRepoPath, stdio: 'pipe' });
      execSync('git commit -m "Add jest"', { cwd: testRepoPath, stdio: 'pipe' });

      const branchName = 'rsolv/validate/issue-realistic';
      execSync(`git checkout -b ${branchName}`, { cwd: testRepoPath, stdio: 'pipe' });

      const issue: IssueContext = {
        number: 7890,
        title: 'Path Traversal',
        body: 'Directory traversal in file download',
        file: 'src/routes/download.js',
        repository: {
          owner: 'OWASP',
          name: 'vulnerable-web-app',
          fullName: 'OWASP/vulnerable-web-app'
        }
      };

      // RED test with realistic attack vector
      const testContent = `
// Based on OWASP pattern: Path traversal
// Vulnerable pattern: res.sendFile(\`/app/uploads/\${filename}\`)
it('should reject path traversal in file download', async () => {
  // REAL attack vector that works in production
  const response = await request(app)
    .get('/download')
    .query({ file: '../../../etc/passwd' });  // Malicious path

  // Test FAILS on vulnerable code (allows traversal)
  expect(response.status).toBe(400);  // Should reject
  expect(response.text).not.toContain('root:x:');  // Should not expose passwd file
});`;

      // Act: Commit with fallback
      await validationMode.commitTestsToBranch(testContent, branchName, issue);

      // Assert: Attack vector should be preserved exactly
      const files = fs.readdirSync(testDir, { recursive: true }) as string[];
      const testFile = files.find(f => f.toString().endsWith('.test.ts') || f.toString().endsWith('.test.js'));

      expect(testFile).toBeDefined();

      const content = fs.readFileSync(path.join(testDir, testFile!), 'utf8');

      // Verify exact attack vector preservation
      expect(content).toContain('../../../etc/passwd');
      expect(content).toContain('root:x:');
      expect(content).toContain('Path traversal');
      expect(content).toContain('OWASP pattern');

      // Verify test structure is maintained
      expect(content).toContain("it('should reject path traversal");
      expect(content).toContain('expect(response.status).toBe(400)');
    });
  });
});
