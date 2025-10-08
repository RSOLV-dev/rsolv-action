/**
 * Tests for TestRunner class that executes framework-specific test commands
 * with timeout handling and structured output capture.
 */

import { describe, test, expect, beforeEach, vi } from 'vitest';

// Mock exec function using vi.hoisted
const mockExecAsync = vi.hoisted(() => vi.fn());

vi.mock('child_process', () => ({
  exec: vi.fn()
}));

vi.mock('util', () => ({
  promisify: () => mockExecAsync
}));

import { TestRunner, type TestRunResult } from '../test-runner.js';

describe('TestRunner', () => {
  let runner: TestRunner;

  beforeEach(() => {
    vi.clearAllMocks();
    runner = new TestRunner();
  });

  describe('Framework Command Execution', () => {
    test('should execute Jest command correctly', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: 'Test suite failed',
        stderr: ''
      } as any);

      const result = await runner.runTests({
        framework: 'jest',
        testFile: 'src/__tests__/user.test.js',
        testName: 'should be vulnerable to SQL injection',
        workingDir: '/tmp/test-repo'
      });

      expect(mockExecAsync).toHaveBeenCalledWith(
        expect.stringContaining('npx jest'),
        expect.objectContaining({
          cwd: '/tmp/test-repo',
          timeout: 30000
        })
      );
      expect(result).toBeDefined();
    });

    test('should execute Vitest command correctly', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: 'Test suite failed',
        stderr: ''
      } as any);

      const result = await runner.runTests({
        framework: 'vitest',
        testFile: 'src/__tests__/user.test.ts',
        testName: 'should be vulnerable to XSS',
        workingDir: '/tmp/test-repo'
      });

      expect(mockExecAsync).toHaveBeenCalledWith(
        expect.stringContaining('npx vitest run'),
        expect.objectContaining({
          cwd: '/tmp/test-repo',
          timeout: 30000
        })
      );
      expect(result).toBeDefined();
    });

    test('should execute RSpec command correctly', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: 'Failures: 1',
        stderr: ''
      } as any);

      const result = await runner.runTests({
        framework: 'rspec',
        testFile: 'spec/user_spec.rb',
        testName: 'should be vulnerable to command injection',
        workingDir: '/tmp/ruby-repo'
      });

      expect(mockExecAsync).toHaveBeenCalledWith(
        expect.stringContaining('bundle exec rspec'),
        expect.objectContaining({
          cwd: '/tmp/ruby-repo',
          timeout: 30000
        })
      );
      expect(result).toBeDefined();
    });

    test('should execute pytest command correctly', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: '1 failed',
        stderr: ''
      } as any);

      const result = await runner.runTests({
        framework: 'pytest',
        testFile: 'tests/test_user.py',
        testName: 'test_sql_injection_vulnerability',
        workingDir: '/tmp/python-repo'
      });

      expect(mockExecAsync).toHaveBeenCalledWith(
        expect.stringContaining('pytest'),
        expect.objectContaining({
          cwd: '/tmp/python-repo',
          timeout: 30000
        })
      );
      expect(result).toBeDefined();
    });

    test('should execute Minitest command correctly', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: '1 failures',
        stderr: ''
      } as any);

      const result = await runner.runTests({
        framework: 'minitest',
        testFile: 'test/user_test.rb',
        testName: 'test_xss_vulnerability',
        workingDir: '/tmp/rails-repo'
      });

      expect(mockExecAsync).toHaveBeenCalledWith(
        'ruby "test/user_test.rb" -n "test_xss_vulnerability"',
        expect.objectContaining({
          cwd: '/tmp/rails-repo',
          timeout: 30000
        })
      );
      expect(result).toBeDefined();
    });

    test('should execute Mocha command correctly', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: '1 failing',
        stderr: ''
      } as any);

      const result = await runner.runTests({
        framework: 'mocha',
        testFile: 'test/security.test.js',
        testName: 'should be vulnerable to XSS',
        workingDir: '/tmp/node-repo'
      });

      expect(mockExecAsync).toHaveBeenCalledWith(
        'npx mocha "test/security.test.js" --grep "should be vulnerable to XSS"',
        expect.objectContaining({
          cwd: '/tmp/node-repo',
          timeout: 30000
        })
      );
      expect(result).toBeDefined();
    });

    test('should execute PHPUnit command correctly', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: 'FAILURES!',
        stderr: ''
      } as any);

      const result = await runner.runTests({
        framework: 'phpunit',
        testFile: 'tests/SecurityTest.php',
        testName: 'testSqlInjectionVulnerability',
        workingDir: '/tmp/php-repo'
      });

      expect(mockExecAsync).toHaveBeenCalledWith(
        'vendor/bin/phpunit "tests/SecurityTest.php" --filter "testSqlInjectionVulnerability"',
        expect.objectContaining({
          cwd: '/tmp/php-repo',
          timeout: 30000
        })
      );
      expect(result).toBeDefined();
    });

    test('should execute JUnit command correctly', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: 'Tests run: 1, Failures: 1',
        stderr: ''
      } as any);

      const result = await runner.runTests({
        framework: 'junit',
        testFile: 'src/test/java/SecurityTest.java',
        testName: 'testSqlInjection',
        workingDir: '/tmp/java-repo'
      });

      expect(mockExecAsync).toHaveBeenCalledWith(
        'mvn test "src/test/java/SecurityTest.java" -Dtest "testSqlInjection"',
        expect.objectContaining({
          cwd: '/tmp/java-repo',
          timeout: 30000
        })
      );
      expect(result).toBeDefined();
    });

    test('should execute Go testing command correctly', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: 'FAIL',
        stderr: ''
      } as any);

      const result = await runner.runTests({
        framework: 'testing',
        testFile: './pkg/security/auth_test.go',
        testName: 'TestSQLInjection',
        workingDir: '/tmp/go-repo'
      });

      expect(mockExecAsync).toHaveBeenCalledWith(
        'go test "./pkg/security/auth_test.go" -run "TestSQLInjection"',
        expect.objectContaining({
          cwd: '/tmp/go-repo',
          timeout: 30000
        })
      );
      expect(result).toBeDefined();
    });

    test('should execute ExUnit command correctly', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: '1 failure',
        stderr: ''
      } as any);

      const result = await runner.runTests({
        framework: 'exunit',
        testFile: 'test/security_test.exs',
        testName: 'test SQL injection vulnerability',
        workingDir: '/tmp/elixir-repo'
      });

      expect(mockExecAsync).toHaveBeenCalledWith(
        'mix test "test/security_test.exs" --only "test SQL injection vulnerability"',
        expect.objectContaining({
          cwd: '/tmp/elixir-repo',
          timeout: 30000
        })
      );
      expect(result).toBeDefined();
    });
  });

  describe('Test Result Detection', () => {
    test('should return failure for vulnerable code (RED test failing)', async () => {
      mockExecAsync.mockRejectedValue({
        code: 1,
        stdout: 'FAIL src/__tests__/user.test.js\n  ✕ should be vulnerable to SQL injection',
        stderr: ''
      } as any);

      const result = await runner.runTests({
        framework: 'jest',
        testFile: 'src/__tests__/user.test.js',
        testName: 'should be vulnerable to SQL injection',
        workingDir: '/tmp/test-repo'
      });

      expect(result.passed).toBe(false);
      expect(result.output).toContain('should be vulnerable to SQL injection');
    });

    test('should return success when RED test passes (catches vulnerability)', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: 'PASS src/__tests__/user.test.js\n  ✓ should be vulnerable to SQL injection',
        stderr: ''
      } as any);

      const result = await runner.runTests({
        framework: 'jest',
        testFile: 'src/__tests__/user.test.js',
        testName: 'should be vulnerable to SQL injection',
        workingDir: '/tmp/test-repo'
      });

      expect(result.passed).toBe(true);
      expect(result.output).toContain('✓');
    });
  });

  describe('Timeout Handling', () => {
    test('should enforce 30-second timeout', async () => {
      mockExecAsync.mockRejectedValue({
        killed: true,
        signal: 'SIGTERM',
        code: null,
        stdout: '',
        stderr: '',
        message: 'Timeout'
      } as any);

      const result = await runner.runTests({
        framework: 'jest',
        testFile: 'src/__tests__/slow.test.js',
        testName: 'very slow test',
        workingDir: '/tmp/test-repo'
      });

      expect(result.timedOut).toBe(true);
      expect(result.passed).toBe(false);
    });

    test('should allow custom timeout override', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: 'Tests passed',
        stderr: ''
      } as any);

      await runner.runTests({
        framework: 'jest',
        testFile: 'src/__tests__/user.test.js',
        testName: 'test',
        workingDir: '/tmp/test-repo',
        timeout: 60000
      });

      expect(mockExecAsync).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          timeout: 60000
        })
      );
    });
  });

  describe('Output Capture', () => {
    test('should capture stdout and stderr', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: 'Test output line 1\nTest output line 2',
        stderr: 'Warning: deprecated API'
      } as any);

      const result = await runner.runTests({
        framework: 'jest',
        testFile: 'src/__tests__/user.test.js',
        testName: 'test',
        workingDir: '/tmp/test-repo'
      });

      expect(result.output).toContain('Test output line 1');
      expect(result.output).toContain('Test output line 2');
      expect(result.stderr).toContain('Warning: deprecated API');
    });

    test('should return structured results', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: 'PASS',
        stderr: ''
      } as any);

      const result = await runner.runTests({
        framework: 'jest',
        testFile: 'src/__tests__/user.test.js',
        testName: 'test',
        workingDir: '/tmp/test-repo'
      });

      expect(result).toHaveProperty('passed');
      expect(result).toHaveProperty('output');
      expect(result).toHaveProperty('stderr');
      expect(result).toHaveProperty('timedOut');
      expect(result).toHaveProperty('exitCode');
      expect(typeof result.passed).toBe('boolean');
      expect(typeof result.output).toBe('string');
      expect(typeof result.timedOut).toBe('boolean');
    });
  });

  describe('Error Handling', () => {
    test('should handle test execution errors gracefully', async () => {
      mockExecAsync.mockRejectedValue(new Error('Command not found'));

      const result = await runner.runTests({
        framework: 'jest',
        testFile: 'src/__tests__/user.test.js',
        testName: 'test',
        workingDir: '/tmp/test-repo'
      });

      expect(result.passed).toBe(false);
      expect(result.error).toBeDefined();
    });

    test('should handle missing test framework gracefully', async () => {
      mockExecAsync.mockRejectedValue({
        code: 127,
        message: 'command not found: jest'
      } as any);

      const result = await runner.runTests({
        framework: 'jest',
        testFile: 'src/__tests__/user.test.js',
        testName: 'test',
        workingDir: '/tmp/test-repo'
      });

      expect(result.passed).toBe(false);
      expect(result.exitCode).toBe(127);
    });
  });
});
