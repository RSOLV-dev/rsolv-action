/**
 * Tests for TestRunner class that executes framework-specific test commands
 * with timeout handling and structured output capture.
 */

import { describe, test, expect, beforeEach, vi } from 'vitest';

// Mock exec function using vi.hoisted
const mockExecAsync = vi.hoisted(() => vi.fn());
const mockFsAccess = vi.hoisted(() => vi.fn());
const mockFsReadFile = vi.hoisted(() => vi.fn().mockResolvedValue(''));

vi.mock('child_process', () => ({
  exec: vi.fn()
}));

vi.mock('util', () => ({
  promisify: () => mockExecAsync
}));

vi.mock('fs/promises', () => ({
  access: mockFsAccess,
  readFile: mockFsReadFile
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

      // RFC-101 v3.8.67+: BUNDLE_IGNORE_RUBY_VERSION=1 added to allow bundler
      // to install gems despite Ruby version mismatch from apt-get fallback
      expect(mockExecAsync).toHaveBeenCalledWith(
        'BUNDLE_IGNORE_RUBY_VERSION=1 ruby "test/user_test.rb" -n "test_xss_vulnerability"',
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

      // RFC-101 v3.8.70: Maven uses ClassName#methodName format, not file path
      // This is the standard Maven Surefire pattern for running specific tests
      expect(mockExecAsync).toHaveBeenCalledWith(
        'mvn test -Dtest="SecurityTest#testSqlInjection"',
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

  describe('Ruby bundle install fallback (booksapp fix)', () => {
    beforeEach(() => {
      mockFsAccess.mockRejectedValue(new Error('ENOENT'));
    });

    test('should fall back to gem install rspec when bundle install fails', async () => {
      // Mock: Gemfile exists
      mockFsAccess.mockImplementation((filePath: string) => {
        if (filePath.endsWith('Gemfile')) return Promise.resolve();
        return Promise.reject(new Error('ENOENT'));
      });

      // Make bundle install fail (e.g., mysql2 native extension error),
      // but subsequent gem install rspec succeeds
      mockExecAsync.mockImplementation((cmd: string) => {
        if (typeof cmd === 'string' && cmd.includes('bundle install')) {
          return Promise.reject(new Error('Gem::Ext::BuildError: Failed to build mysql2'));
        }
        return Promise.resolve({ stdout: '', stderr: '' });
      });

      await runner.runTests({
        framework: 'rspec',
        testFile: 'spec/vulnerability_spec.rb',
        testName: 'test vulnerability',
        workingDir: '/tmp/ruby-repo'
      });

      const calls = mockExecAsync.mock.calls.map((c: unknown[]) => c[0] as string);
      // Should have attempted gem install rspec as fallback
      const gemInstallCall = calls.find((c: string) => c.includes('gem install rspec'));
      expect(gemInstallCall).toBeDefined();
    });

    test('should use rspec directly (not bundle exec) when bundle install failed', async () => {
      // Mock: Gemfile exists
      mockFsAccess.mockImplementation((filePath: string) => {
        if (filePath.endsWith('Gemfile')) return Promise.resolve();
        return Promise.reject(new Error('ENOENT'));
      });

      // Make bundle install fail, gem install succeeds, test execution resolves
      mockExecAsync.mockImplementation((cmd: string) => {
        if (typeof cmd === 'string' && cmd.includes('bundle install')) {
          return Promise.reject(new Error('Gem::Ext::BuildError: Failed to build mysql2'));
        }
        return Promise.resolve({ stdout: 'Failures: 1', stderr: '' });
      });

      await runner.runTests({
        framework: 'rspec',
        testFile: 'spec/vulnerability_spec.rb',
        testName: 'test vulnerability',
        workingDir: '/tmp/ruby-repo'
      });

      const calls = mockExecAsync.mock.calls.map((c: unknown[]) => c[0] as string);
      // The test execution command should use rspec directly, not bundle exec rspec
      const testCall = calls.find((c: string) =>
        c.includes('rspec') && c.includes('spec/vulnerability_spec.rb') && !c.includes('bundle exec')
      );
      expect(testCall).toBeDefined();
    });

    test('should expose bundleInstallFailed flag for external consumers (validation-mode.ts)', async () => {
      // validation-mode.ts creates a TestRunner for setup, then uses its own runTest() method.
      // It needs to check TestRunner.bundleInstallFailed to know whether to use 'rspec' vs 'bundle exec rspec'.
      mockFsAccess.mockImplementation((filePath: string) => {
        if (filePath.endsWith('Gemfile')) return Promise.resolve();
        return Promise.reject(new Error('ENOENT'));
      });

      // Make bundle install fail, gem install rspec succeeds
      mockExecAsync.mockImplementation((cmd: string) => {
        if (typeof cmd === 'string' && cmd.includes('bundle install')) {
          return Promise.reject(new Error('Gem::Ext::BuildError: Failed to build mysql2'));
        }
        return Promise.resolve({ stdout: '', stderr: '' });
      });

      // Verify flag is false before ensureDependencies
      expect(runner.bundleInstallFailed).toBe(false);

      await runner.ensureDependencies('rspec', '/tmp/ruby-repo');

      // After ensureDependencies with bundle install failure, flag should be true
      expect(runner.bundleInstallFailed).toBe(true);
    });

    test('should still use bundle exec rspec when bundle install succeeds', async () => {
      // Mock: Gemfile exists
      mockFsAccess.mockImplementation((filePath: string) => {
        if (filePath.endsWith('Gemfile')) return Promise.resolve();
        return Promise.reject(new Error('ENOENT'));
      });

      // Everything succeeds
      mockExecAsync.mockResolvedValue({ stdout: 'Failures: 1', stderr: '' });

      await runner.runTests({
        framework: 'rspec',
        testFile: 'spec/vulnerability_spec.rb',
        testName: 'test vulnerability',
        workingDir: '/tmp/ruby-repo'
      });

      const calls = mockExecAsync.mock.calls.map((c: unknown[]) => c[0] as string);
      // Test execution should use bundle exec rspec
      const testCall = calls.find((c: string) =>
        c.includes('bundle exec rspec') && c.includes('spec/vulnerability_spec.rb')
      );
      expect(testCall).toBeDefined();
      // Should NOT have called gem install rspec
      const gemInstallCall = calls.find((c: string) => c.includes('gem install rspec'));
      expect(gemInstallCall).toBeUndefined();
    });
  });

  describe('Dependency Install Commands (RFC-101 v3.8.71)', () => {
    beforeEach(() => {
      // Reset fs mock - default to file not existing
      mockFsAccess.mockRejectedValue(new Error('ENOENT'));
    });

    test('PHP: should use --ignore-platform-reqs for composer install', async () => {
      // Mock: composer.json exists, vendor/autoload.php doesn't
      mockFsAccess.mockImplementation((filePath: string) => {
        if (filePath.endsWith('composer.json')) return Promise.resolve();
        if (filePath.endsWith('autoload.php')) return Promise.reject(new Error('ENOENT'));
        return Promise.reject(new Error('ENOENT'));
      });

      mockExecAsync.mockResolvedValue({ stdout: '', stderr: '' });

      await runner.runTests({
        framework: 'phpunit',
        testFile: 'tests/SecurityTest.php',
        testName: 'testVulnerability',
        workingDir: '/tmp/php-repo'
      });

      // Verify composer install includes --ignore-platform-reqs
      const calls = mockExecAsync.mock.calls;
      const composerCall = calls.find((call: unknown[]) =>
        typeof call[0] === 'string' && call[0].includes('composer install')
      );
      expect(composerCall).toBeDefined();
      expect(composerCall![0]).toContain('--ignore-platform-reqs');
    });

    test('Elixir: should set MIX_ENV=test for proper test isolation', async () => {
      // Mock: mix.exs exists
      mockFsAccess.mockImplementation((filePath: string) => {
        if (filePath.endsWith('mix.exs')) return Promise.resolve();
        return Promise.reject(new Error('ENOENT'));
      });

      mockExecAsync.mockResolvedValue({ stdout: '', stderr: '' });

      await runner.runTests({
        framework: 'exunit',
        testFile: 'test/security_test.exs',
        testName: 'test vulnerability',
        workingDir: '/tmp/elixir-repo'
      });

      // Verify mix deps command sets MIX_ENV=test for proper test isolation
      const calls = mockExecAsync.mock.calls;
      const mixDepsCall = calls.find((call: unknown[]) =>
        typeof call[0] === 'string' && call[0].includes('mix deps')
      );
      expect(mixDepsCall).toBeDefined();
      expect(mixDepsCall![0]).toContain('MIX_ENV=test');
    });
  });

  describe('Python Dependency Install — uv default (RFC-103)', () => {
    beforeEach(() => {
      mockFsAccess.mockRejectedValue(new Error('ENOENT'));
    });

    test('should use uv pip install --system --break-system-packages as default', async () => {
      // All file checks fail (no lock files, no manifests)
      mockFsAccess.mockRejectedValue(new Error('ENOENT'));
      // Default mock: which python, which uv, and install all succeed
      mockExecAsync.mockResolvedValue({ stdout: '', stderr: '' });

      await runner.runTests({
        framework: 'pytest',
        testFile: 'tests/test_security.py',
        testName: 'test_vulnerability',
        workingDir: '/tmp/python-repo'
      });

      const calls = mockExecAsync.mock.calls;
      const installCall = calls.find((call: unknown[]) =>
        typeof call[0] === 'string' && call[0].includes('uv pip install')
      );
      expect(installCall).toBeDefined();
      expect(installCall![0]).toContain('uv pip install --system --break-system-packages');
      expect(installCall![0]).toContain('pytest');
    });

    test('should use uv pip install with requirements.txt', async () => {
      mockFsAccess.mockImplementation((filePath: string) => {
        if (filePath.endsWith('requirements.txt')) return Promise.resolve();
        return Promise.reject(new Error('ENOENT'));
      });
      mockExecAsync.mockResolvedValue({ stdout: '', stderr: '' });

      await runner.runTests({
        framework: 'pytest',
        testFile: 'tests/test_security.py',
        testName: 'test_vulnerability',
        workingDir: '/tmp/python-repo'
      });

      const calls = mockExecAsync.mock.calls;
      const installCall = calls.find((call: unknown[]) =>
        typeof call[0] === 'string' && call[0].includes('requirements.txt')
      );
      expect(installCall).toBeDefined();
      expect(installCall![0]).toContain('uv pip install --system --break-system-packages -r requirements.txt');
      expect(installCall![0]).toContain('uv pip install --system --break-system-packages pytest');
    });

    test('should use uv pip install with pyproject.toml', async () => {
      mockFsAccess.mockImplementation((filePath: string) => {
        if (filePath.endsWith('pyproject.toml')) return Promise.resolve();
        return Promise.reject(new Error('ENOENT'));
      });
      mockExecAsync.mockResolvedValue({ stdout: '', stderr: '' });

      await runner.runTests({
        framework: 'pytest',
        testFile: 'tests/test_security.py',
        testName: 'test_vulnerability',
        workingDir: '/tmp/python-repo'
      });

      const calls = mockExecAsync.mock.calls;
      const installCall = calls.find((call: unknown[]) =>
        typeof call[0] === 'string' && call[0].includes('uv pip install --system --break-system-packages -e .')
      );
      expect(installCall).toBeDefined();
      expect(installCall![0]).toContain('uv pip install --system --break-system-packages pytest');
    });

    test('should detect poetry.lock and use poetry install', async () => {
      mockFsAccess.mockImplementation((filePath: string) => {
        if (filePath.endsWith('poetry.lock')) return Promise.resolve();
        return Promise.reject(new Error('ENOENT'));
      });
      mockExecAsync.mockResolvedValue({ stdout: '', stderr: '' });

      await runner.runTests({
        framework: 'pytest',
        testFile: 'tests/test_security.py',
        testName: 'test_vulnerability',
        workingDir: '/tmp/python-repo'
      });

      const calls = mockExecAsync.mock.calls;
      const installCall = calls.find((call: unknown[]) =>
        typeof call[0] === 'string' && call[0].includes('poetry install')
      );
      expect(installCall).toBeDefined();
      // Should use poetry run for test execution
      const testCall = calls.find((call: unknown[]) =>
        typeof call[0] === 'string' && call[0].includes('poetry run pytest')
      );
      expect(testCall).toBeDefined();
    });

    test('should detect Pipfile.lock and use pipenv install', async () => {
      mockFsAccess.mockImplementation((filePath: string) => {
        if (filePath.endsWith('Pipfile.lock')) return Promise.resolve();
        return Promise.reject(new Error('ENOENT'));
      });
      mockExecAsync.mockResolvedValue({ stdout: '', stderr: '' });

      await runner.runTests({
        framework: 'pytest',
        testFile: 'tests/test_security.py',
        testName: 'test_vulnerability',
        workingDir: '/tmp/python-repo'
      });

      const calls = mockExecAsync.mock.calls;
      const installCall = calls.find((call: unknown[]) =>
        typeof call[0] === 'string' && call[0].includes('pipenv install')
      );
      expect(installCall).toBeDefined();
      // Should use pipenv run for test execution
      const testCall = calls.find((call: unknown[]) =>
        typeof call[0] === 'string' && call[0].includes('pipenv run pytest')
      );
      expect(testCall).toBeDefined();
    });

    test('should detect uv.lock and use uv sync', async () => {
      mockFsAccess.mockImplementation((filePath: string) => {
        if (filePath.endsWith('uv.lock')) return Promise.resolve();
        return Promise.reject(new Error('ENOENT'));
      });
      mockExecAsync.mockResolvedValue({ stdout: '', stderr: '' });

      await runner.runTests({
        framework: 'pytest',
        testFile: 'tests/test_security.py',
        testName: 'test_vulnerability',
        workingDir: '/tmp/python-repo'
      });

      const calls = mockExecAsync.mock.calls;
      const installCall = calls.find((call: unknown[]) =>
        typeof call[0] === 'string' && call[0].includes('uv sync')
      );
      expect(installCall).toBeDefined();
      // Should use uv run for test execution
      const testCall = calls.find((call: unknown[]) =>
        typeof call[0] === 'string' && call[0].includes('uv run pytest')
      );
      expect(testCall).toBeDefined();
    });

    test('should fall back to pip with --break-system-packages when uv unavailable', async () => {
      // No lock files, no manifests
      mockFsAccess.mockRejectedValue(new Error('ENOENT'));
      // Make 'which uv' fail and curl install fail — forces pip fallback
      mockExecAsync.mockImplementation((cmd: string) => {
        if (typeof cmd === 'string' && cmd === 'which uv') {
          return Promise.reject(new Error('not found'));
        }
        if (typeof cmd === 'string' && cmd.includes('astral.sh/uv')) {
          return Promise.reject(new Error('curl failed'));
        }
        return Promise.resolve({ stdout: '', stderr: '' });
      });

      await runner.runTests({
        framework: 'pytest',
        testFile: 'tests/test_security.py',
        testName: 'test_vulnerability',
        workingDir: '/tmp/python-repo'
      });

      const calls = mockExecAsync.mock.calls;
      const installCall = calls.find((call: unknown[]) =>
        typeof call[0] === 'string' && call[0].includes('pip install') && call[0].includes('pytest')
      );
      expect(installCall).toBeDefined();
      expect(installCall![0]).toContain('--break-system-packages');
      expect(installCall![0]).not.toContain('uv');
    });

    test('should fall back to pip with requirements.txt when uv unavailable', async () => {
      mockFsAccess.mockImplementation((filePath: string) => {
        if (filePath.endsWith('requirements.txt')) return Promise.resolve();
        return Promise.reject(new Error('ENOENT'));
      });
      mockExecAsync.mockImplementation((cmd: string) => {
        if (typeof cmd === 'string' && cmd === 'which uv') {
          return Promise.reject(new Error('not found'));
        }
        if (typeof cmd === 'string' && cmd.includes('astral.sh/uv')) {
          return Promise.reject(new Error('curl failed'));
        }
        return Promise.resolve({ stdout: '', stderr: '' });
      });

      await runner.runTests({
        framework: 'pytest',
        testFile: 'tests/test_security.py',
        testName: 'test_vulnerability',
        workingDir: '/tmp/python-repo'
      });

      const calls = mockExecAsync.mock.calls;
      const installCall = calls.find((call: unknown[]) =>
        typeof call[0] === 'string' && call[0].includes('requirements.txt') && call[0].includes('pip install')
      );
      expect(installCall).toBeDefined();
      expect(installCall![0]).toContain('--break-system-packages');
      expect(installCall![0]).toContain('--break-system-packages pytest');
    });

    test('should install poetry via uv when poetry.lock detected but poetry not available', async () => {
      mockFsAccess.mockImplementation((filePath: string) => {
        if (filePath.endsWith('poetry.lock')) return Promise.resolve();
        return Promise.reject(new Error('ENOENT'));
      });
      mockExecAsync.mockResolvedValue({ stdout: '', stderr: '' });

      await runner.runTests({
        framework: 'pytest',
        testFile: 'tests/test_security.py',
        testName: 'test_vulnerability',
        workingDir: '/tmp/python-repo'
      });

      const calls = mockExecAsync.mock.calls;
      const installCall = calls.find((call: unknown[]) =>
        typeof call[0] === 'string' && call[0].includes('uv pip install --system --break-system-packages poetry')
      );
      expect(installCall).toBeDefined();
    });
  });

  describe('Java Version Detection (RFC-103)', () => {
    beforeEach(() => {
      mockFsAccess.mockRejectedValue(new Error('ENOENT'));
      mockFsReadFile.mockResolvedValue('');
    });

    test('should detect sourceCompatibility from build.gradle', async () => {
      mockFsAccess.mockImplementation((filePath: string) => {
        if (filePath.endsWith('build.gradle')) return Promise.resolve();
        return Promise.reject(new Error('ENOENT'));
      });
      mockFsReadFile.mockImplementation((filePath: string) => {
        if (filePath.endsWith('build.gradle')) {
          return Promise.resolve(`
            plugins {
              id 'java'
            }
            sourceCompatibility = 11
            targetCompatibility = 11
          `);
        }
        return Promise.resolve('');
      });

      const version = await runner.detectJavaVersionFromManifest('/tmp/java-repo');
      expect(version).toBe('11');
    });

    test('should detect JavaVersion.VERSION_X format', async () => {
      mockFsAccess.mockImplementation((filePath: string) => {
        if (filePath.endsWith('build.gradle')) return Promise.resolve();
        return Promise.reject(new Error('ENOENT'));
      });
      mockFsReadFile.mockImplementation((filePath: string) => {
        if (filePath.endsWith('build.gradle')) {
          return Promise.resolve(`
            sourceCompatibility = JavaVersion.VERSION_17
          `);
        }
        return Promise.resolve('');
      });

      const version = await runner.detectJavaVersionFromManifest('/tmp/java-repo');
      expect(version).toBe('17');
    });

    test('should ignore sourceCompatibility in block comments', async () => {
      mockFsAccess.mockImplementation((filePath: string) => {
        if (filePath.endsWith('build.gradle')) return Promise.resolve();
        return Promise.reject(new Error('ENOENT'));
      });
      mockFsReadFile.mockImplementation((filePath: string) => {
        if (filePath.endsWith('build.gradle')) {
          // Simulates the JavaSpringVulny case: commented-out Java 8, actual Java 11
          return Promise.resolve(`
            plugins {
              id 'java'
            }
            /*
             * Legacy settings for Java 8
             * sourceCompatibility = 1.8
             */
            sourceCompatibility = 11
          `);
        }
        return Promise.resolve('');
      });

      const version = await runner.detectJavaVersionFromManifest('/tmp/java-repo');
      // Should match 11, not 8 from the comment
      expect(version).toBe('11');
    });

    test('should ignore sourceCompatibility in single-line comments', async () => {
      mockFsAccess.mockImplementation((filePath: string) => {
        if (filePath.endsWith('build.gradle')) return Promise.resolve();
        return Promise.reject(new Error('ENOENT'));
      });
      mockFsReadFile.mockImplementation((filePath: string) => {
        if (filePath.endsWith('build.gradle')) {
          return Promise.resolve(`
            // sourceCompatibility = 1.8
            sourceCompatibility = 17
          `);
        }
        return Promise.resolve('');
      });

      const version = await runner.detectJavaVersionFromManifest('/tmp/java-repo');
      expect(version).toBe('17');
    });

    test('should detect Java version from pom.xml java.version property', async () => {
      mockFsAccess.mockImplementation((filePath: string) => {
        if (filePath.endsWith('pom.xml')) return Promise.resolve();
        return Promise.reject(new Error('ENOENT'));
      });
      mockFsReadFile.mockImplementation((filePath: string) => {
        if (filePath.endsWith('pom.xml')) {
          return Promise.resolve(`
            <project>
              <properties>
                <java.version>21</java.version>
              </properties>
            </project>
          `);
        }
        return Promise.resolve('');
      });

      const version = await runner.detectJavaVersionFromManifest('/tmp/java-repo');
      expect(version).toBe('21');
    });

    test('should use temurin vendor prefix for mise Java installation', async () => {
      mockFsAccess.mockImplementation((filePath: string) => {
        if (filePath.endsWith('build.gradle')) return Promise.resolve();
        return Promise.reject(new Error('ENOENT'));
      });
      mockFsReadFile.mockImplementation((filePath: string) => {
        if (filePath.endsWith('build.gradle')) {
          return Promise.resolve('sourceCompatibility = 11');
        }
        return Promise.resolve('');
      });
      // Make 'which java' fail first (so ensureRuntime triggers installation)
      // then make everything else succeed
      mockExecAsync.mockImplementation((cmd: string) => {
        if (typeof cmd === 'string' && cmd === 'which java') {
          return Promise.reject(new Error('not found'));
        }
        return Promise.resolve({ stdout: '', stderr: '' });
      });

      await runner.runTests({
        framework: 'junit4',
        testFile: 'src/test/java/SecurityTest.java',
        testName: 'testVulnerability',
        workingDir: '/tmp/java-repo'
      });

      const calls = mockExecAsync.mock.calls.map((c: unknown[]) => c[0] as string);
      // Should use temurin vendor prefix for mise installation
      const miseCall = calls.find((c: string) => c.includes('mise install java@temurin-'));
      expect(miseCall).toBeDefined();
      expect(miseCall).toContain('java@temurin-11');
    });
  });

  describe('Mise Data Directory Helpers (RFC-105)', () => {
    test('getMiseDataDir returns default path when MISE_DATA_DIR is not set', () => {
      const originalMiseDataDir = process.env.MISE_DATA_DIR;
      const originalHome = process.env.HOME;
      delete process.env.MISE_DATA_DIR;
      process.env.HOME = '/root';

      // Access private method via any cast for testing
      const dir = (runner as any).getMiseDataDir();
      expect(dir).toBe('/root/.local/share/mise');

      // Cleanup
      if (originalMiseDataDir) process.env.MISE_DATA_DIR = originalMiseDataDir;
      else delete process.env.MISE_DATA_DIR;
      if (originalHome) process.env.HOME = originalHome;
      else delete process.env.HOME;
    });

    test('getMiseDataDir returns custom path when MISE_DATA_DIR is set', () => {
      const originalMiseDataDir = process.env.MISE_DATA_DIR;
      process.env.MISE_DATA_DIR = '/custom/mise/data';

      const dir = (runner as any).getMiseDataDir();
      expect(dir).toBe('/custom/mise/data');

      // Cleanup
      if (originalMiseDataDir) process.env.MISE_DATA_DIR = originalMiseDataDir;
      else delete process.env.MISE_DATA_DIR;
    });

    test('getMiseShimsPath derives from getMiseDataDir', () => {
      const originalMiseDataDir = process.env.MISE_DATA_DIR;
      delete process.env.MISE_DATA_DIR;
      process.env.HOME = '/root';

      const shimsPath = (runner as any).getMiseShimsPath();
      expect(shimsPath).toBe('/root/.local/share/mise/shims');

      // Cleanup
      if (originalMiseDataDir) process.env.MISE_DATA_DIR = originalMiseDataDir;
      else delete process.env.MISE_DATA_DIR;
    });

    test('getMiseShimsPath uses custom MISE_DATA_DIR', () => {
      const originalMiseDataDir = process.env.MISE_DATA_DIR;
      process.env.MISE_DATA_DIR = '/custom/mise/data';

      const shimsPath = (runner as any).getMiseShimsPath();
      expect(shimsPath).toBe('/custom/mise/data/shims');

      // Cleanup
      if (originalMiseDataDir) process.env.MISE_DATA_DIR = originalMiseDataDir;
      else delete process.env.MISE_DATA_DIR;
    });
  });

  describe('PostgreSQL Provisioning (RFC-103 B1)', () => {
    beforeEach(() => {
      mockFsAccess.mockRejectedValue(new Error('ENOENT'));
      mockFsReadFile.mockResolvedValue('');
    });

    test('needsPostgresql returns true when mix.exs contains {:postgrex', async () => {
      mockFsAccess.mockImplementation((filePath: string) => {
        if (filePath.endsWith('mix.exs')) return Promise.resolve();
        return Promise.reject(new Error('ENOENT'));
      });
      mockFsReadFile.mockImplementation((filePath: string) => {
        if (filePath.endsWith('mix.exs')) {
          return Promise.resolve(`
            defp deps do
              [{:phoenix, "~> 1.7"}, {:postgrex, ">= 0.0.0"}, {:ecto_sql, "~> 3.10"}]
            end
          `);
        }
        return Promise.resolve('');
      });

      const result = await runner.needsPostgresql('/tmp/elixir-repo');
      expect(result).toBe(true);
    });

    test('needsPostgresql returns true when mix.exs contains {:ecto_sql', async () => {
      mockFsAccess.mockImplementation((filePath: string) => {
        if (filePath.endsWith('mix.exs')) return Promise.resolve();
        return Promise.reject(new Error('ENOENT'));
      });
      mockFsReadFile.mockImplementation((filePath: string) => {
        if (filePath.endsWith('mix.exs')) {
          return Promise.resolve(`
            defp deps do
              [{:phoenix, "~> 1.7"}, {:ecto_sql, "~> 3.10"}]
            end
          `);
        }
        return Promise.resolve('');
      });

      const result = await runner.needsPostgresql('/tmp/elixir-repo');
      expect(result).toBe(true);
    });

    test('needsPostgresql returns false when mix.exs has no database deps', async () => {
      mockFsAccess.mockImplementation((filePath: string) => {
        if (filePath.endsWith('mix.exs')) return Promise.resolve();
        return Promise.reject(new Error('ENOENT'));
      });
      mockFsReadFile.mockImplementation((filePath: string) => {
        if (filePath.endsWith('mix.exs')) {
          return Promise.resolve(`
            defp deps do
              [{:phoenix, "~> 1.7"}, {:jason, "~> 1.4"}]
            end
          `);
        }
        return Promise.resolve('');
      });

      const result = await runner.needsPostgresql('/tmp/elixir-repo');
      expect(result).toBe(false);
    });

    test('needsPostgresql returns false for non-Elixir projects', async () => {
      // No mix.exs file
      mockFsAccess.mockRejectedValue(new Error('ENOENT'));

      const result = await runner.needsPostgresql('/tmp/node-repo');
      expect(result).toBe(false);
    });

    test('ensurePostgresql starts PostgreSQL and creates test database', async () => {
      mockFsAccess.mockImplementation((filePath: string) => {
        if (filePath.endsWith('mix.exs')) return Promise.resolve();
        return Promise.reject(new Error('ENOENT'));
      });
      mockFsReadFile.mockImplementation((filePath: string) => {
        if (filePath.endsWith('mix.exs')) {
          return Promise.resolve(`
            def project do
              [app: :potion_shop, version: "0.1.0"]
            end
          `);
        }
        return Promise.resolve('');
      });

      // pg_isready fails first (PostgreSQL not running), then succeeds after start
      let pgReadyCalls = 0;
      mockExecAsync.mockImplementation((cmd: string) => {
        if (typeof cmd === 'string' && cmd.includes('pg_isready')) {
          pgReadyCalls++;
          if (pgReadyCalls === 1) return Promise.reject(new Error('not running'));
          return Promise.resolve({ stdout: 'accepting connections', stderr: '' });
        }
        return Promise.resolve({ stdout: '', stderr: '' });
      });

      await runner.ensurePostgresql('/tmp/elixir-repo');

      const calls = mockExecAsync.mock.calls.map((c: unknown[]) => c[0] as string);

      // Should check pg_isready
      expect(calls.some((c: string) => c.includes('pg_isready'))).toBe(true);
      // Should start PostgreSQL
      expect(calls.some((c: string) => c.includes('pg_ctlcluster') || c.includes('pg_ctl'))).toBe(true);
      // Should create user and database
      expect(calls.some((c: string) => c.includes('createuser'))).toBe(true);
      expect(calls.some((c: string) => c.includes('createdb') && c.includes('potion_shop_test'))).toBe(true);

      // Should set DATABASE_URL
      expect(process.env.DATABASE_URL).toContain('potion_shop_test');
      expect(process.env.MIX_ENV).toBe('test');
    });

    test('ensurePostgresql skips start if PostgreSQL is already running', async () => {
      mockFsReadFile.mockImplementation((filePath: string) => {
        if (filePath.endsWith('mix.exs')) {
          return Promise.resolve('def project do [app: :my_app] end');
        }
        return Promise.resolve('');
      });

      // pg_isready succeeds immediately
      mockExecAsync.mockResolvedValue({ stdout: 'accepting connections', stderr: '' });

      await runner.ensurePostgresql('/tmp/elixir-repo');

      const calls = mockExecAsync.mock.calls.map((c: unknown[]) => c[0] as string);

      // Should NOT start PostgreSQL (already running)
      expect(calls.some((c: string) => c.includes('pg_ctlcluster'))).toBe(false);
      // Should still create user and database
      expect(calls.some((c: string) => c.includes('createuser'))).toBe(true);
    });

    test('ensurePostgresql sets DATABASE_URL in process.env', async () => {
      const originalDbUrl = process.env.DATABASE_URL;
      const originalMixEnv = process.env.MIX_ENV;

      mockFsReadFile.mockImplementation((filePath: string) => {
        if (filePath.endsWith('mix.exs')) {
          return Promise.resolve('def project do [app: :test_app] end');
        }
        return Promise.resolve('');
      });
      mockExecAsync.mockResolvedValue({ stdout: '', stderr: '' });

      await runner.ensurePostgresql('/tmp/elixir-repo');

      expect(process.env.DATABASE_URL).toBe('postgresql://postgres:postgres@localhost/test_app_test');
      expect(process.env.MIX_ENV).toBe('test');

      // Cleanup
      if (originalDbUrl) process.env.DATABASE_URL = originalDbUrl;
      else delete process.env.DATABASE_URL;
      if (originalMixEnv) process.env.MIX_ENV = originalMixEnv;
      else delete process.env.MIX_ENV;
    });

    test('Elixir ensureDependencies calls ensurePostgresql when project needs it', async () => {
      mockFsAccess.mockImplementation((filePath: string) => {
        if (filePath.endsWith('mix.exs')) return Promise.resolve();
        return Promise.reject(new Error('ENOENT'));
      });
      mockFsReadFile.mockImplementation((filePath: string) => {
        if (filePath.endsWith('mix.exs')) {
          return Promise.resolve(`
            def project do [app: :my_app] end
            defp deps do [{:postgrex, ">= 0.0.0"}] end
          `);
        }
        return Promise.resolve('');
      });
      mockExecAsync.mockResolvedValue({ stdout: '', stderr: '' });

      await runner.runTests({
        framework: 'exunit',
        testFile: 'test/security_test.exs',
        testName: 'test vulnerability',
        workingDir: '/tmp/elixir-repo'
      });

      const calls = mockExecAsync.mock.calls.map((c: unknown[]) => c[0] as string);

      // Should have called pg_isready (PostgreSQL provisioning)
      expect(calls.some((c: string) => c.includes('pg_isready'))).toBe(true);
      // Should include ecto.create and ecto.migrate in dep command
      const mixCall = calls.find((c: string) => c.includes('mix deps'));
      expect(mixCall).toBeDefined();
      expect(mixCall).toContain('ecto.create');
      expect(mixCall).toContain('ecto.migrate');
    });
  });
});
