/**
 * Test suite for test result classification
 *
 * RFC-060-AMENDMENT-001: Comprehensive tests for classifying test execution
 * results to distinguish real test failures (vulnerability proven) from
 * errors (syntax, missing deps, etc.)
 *
 * Exit codes alone are insufficient - we need to examine stderr/stdout
 * to properly classify results.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { ValidationMode } from '../validation-mode.js';
import { parseTestOutputCounts } from '../../utils/test-result-classifier.js';
import { createTestConfig, type TestResultClassification } from './test-fixtures.js';

describe('Test Result Classification', () => {
  let validationMode: ValidationMode;

  beforeEach(() => {
    const config = createTestConfig();
    validationMode = new ValidationMode(config);
  });

  describe('Exit Code Based Classification', () => {
    it('should classify exit code 0 as test passed (not valid failure)', () => {
      const result = validationMode.classifyTestResult(0, 'All tests passed', '');

      expect(result.type).toBe('test_passed');
      expect(result.isValidFailure).toBe(false);
      expect(result.reason).toMatch(/passed|not proven/i);
    });

    it('should classify exit code 127 as command not found', () => {
      const stderr = 'vitest: command not found';
      const result = validationMode.classifyTestResult(127, '', stderr);

      expect(result.type).toBe('command_not_found');
      expect(result.isValidFailure).toBe(false);
      expect(result.reason).toMatch(/not found|not installed/i);
    });

    it('should classify exit code 137 as OOM killed', () => {
      const result = validationMode.classifyTestResult(137, '', '');

      expect(result.type).toBe('oom_killed');
      expect(result.isValidFailure).toBe(false);
      expect(result.reason).toMatch(/memory|killed/i);
    });

    it('should classify exit code 143 as terminated', () => {
      const result = validationMode.classifyTestResult(143, '', '');

      expect(result.type).toBe('terminated');
      expect(result.isValidFailure).toBe(false);
      expect(result.reason).toMatch(/terminated|interrupted/i);
    });

    it('should classify exit code 130 as interrupted (SIGINT)', () => {
      const result = validationMode.classifyTestResult(130, '', '');

      expect(result.type).toBe('terminated');
      expect(result.isValidFailure).toBe(false);
    });
  });

  describe('Syntax Error Detection', () => {
    it('should detect JavaScript SyntaxError', () => {
      const stderr = `
SyntaxError: Unexpected token '{'
    at Parser.parseStatement (internal/deps/acorn/acorn/dist/acorn.js:123:45)
      `;
      const result = validationMode.classifyTestResult(1, '', stderr);

      expect(result.type).toBe('syntax_error');
      expect(result.isValidFailure).toBe(false);
      expect(result.reason).toMatch(/syntax/i);
    });

    it('should detect unexpected end of input', () => {
      const stderr = 'SyntaxError: Unexpected end of input';
      const result = validationMode.classifyTestResult(1, '', stderr);

      expect(result.type).toBe('syntax_error');
      expect(result.isValidFailure).toBe(false);
    });

    it('should detect unexpected token errors', () => {
      const stderr = 'SyntaxError: Unexpected token \'else\'';
      const result = validationMode.classifyTestResult(1, '', stderr);

      expect(result.type).toBe('syntax_error');
      expect(result.isValidFailure).toBe(false);
    });

    it('should detect Python syntax errors', () => {
      const stderr = `
  File "test_user.py", line 10
    if x = 5:
         ^
SyntaxError: invalid syntax
      `;
      const result = validationMode.classifyTestResult(1, '', stderr);

      expect(result.type).toBe('syntax_error');
      expect(result.isValidFailure).toBe(false);
    });

    it('should detect Ruby syntax errors', () => {
      const stderr = `
user_spec.rb:15: syntax error, unexpected keyword_end
      `;
      const result = validationMode.classifyTestResult(1, '', stderr);

      expect(result.type).toBe('syntax_error');
      expect(result.isValidFailure).toBe(false);
    });
  });

  describe('Runtime Error Detection', () => {
    it('should detect ReferenceError (undefined variable)', () => {
      const stderr = `
ReferenceError: undefinedVariable is not defined
    at Object.<anonymous> (test.js:5:1)
      `;
      const result = validationMode.classifyTestResult(1, '', stderr);

      expect(result.type).toBe('runtime_error');
      expect(result.isValidFailure).toBe(false);
      expect(result.reason).toMatch(/reference|undefined/i);
    });

    it('should detect "is not defined" errors', () => {
      const stderr = 'ReferenceError: detectSQLInjection is not defined';
      const result = validationMode.classifyTestResult(1, '', stderr);

      expect(result.type).toBe('runtime_error');
      expect(result.isValidFailure).toBe(false);
    });

    it('should detect TypeError for missing functions', () => {
      const stderr = 'TypeError: x.someMethod is not a function';
      const result = validationMode.classifyTestResult(1, '', stderr);

      expect(result.type).toBe('runtime_error');
      expect(result.isValidFailure).toBe(false);
    });

    // RFC-101 v3.8.71: Database unavailable patterns
    it('should detect Ecto database creation failure (Elixir)', () => {
      const stderr = '** (Mix) The database for Carafe.Repo couldn\'t be created: killed';
      const result = validationMode.classifyTestResult(1, '', stderr);

      expect(result.type).toBe('runtime_error');
      expect(result.isValidFailure).toBe(false);
      expect(result.reason).toMatch(/database|PostgreSQL/i);
    });

    it('should detect PostgreSQL connection refused', () => {
      const stderr = 'could not connect to server: Connection refused\n\tIs the server running on host "localhost"?';
      const result = validationMode.classifyTestResult(1, '', stderr);

      expect(result.type).toBe('runtime_error');
      expect(result.isValidFailure).toBe(false);
      expect(result.reason).toMatch(/PostgreSQL|connection/i);
    });

    it('should detect MySQL connection failure', () => {
      const stderr = "Can't connect to MySQL server on 'localhost'";
      const result = validationMode.classifyTestResult(1, '', stderr);

      expect(result.type).toBe('runtime_error');
      expect(result.isValidFailure).toBe(false);
      expect(result.reason).toMatch(/MySQL/i);
    });
  });

  describe('Test File Discovery Errors', () => {
    it('should detect vitest "No test files found" as runtime_error', () => {
      const stdout = `No test files found, exiting with code 1\n\nfilter: /github/workspace/__tests__/vulnerability_validation.ts\ninclude: **/*.{test,spec}.?(c|m)[jt]s?(x)`;
      const result = validationMode.classifyTestResult(1, stdout, '');

      expect(result.type).toBe('runtime_error');
      expect(result.isValidFailure).toBe(false);
      expect(result.reason).toMatch(/No test files found/i);
    });
  });

  describe('Missing Dependency Detection', () => {
    it('should detect Cannot find module error (Node.js)', () => {
      const stderr = `
Error: Cannot find module 'express'
    at Function.Module._resolveFilename (internal/modules/cjs/loader.js:636:15)
      `;
      const result = validationMode.classifyTestResult(1, '', stderr);

      expect(result.type).toBe('missing_dependency');
      expect(result.isValidFailure).toBe(false);
      expect(result.reason).toMatch(/dependency|module/i);
    });

    it('should detect ModuleNotFoundError (Python)', () => {
      const stderr = 'ModuleNotFoundError: No module named \'django\'';
      const result = validationMode.classifyTestResult(1, '', stderr);

      expect(result.type).toBe('missing_dependency');
      expect(result.isValidFailure).toBe(false);
    });

    it('should detect No module named error (Python)', () => {
      const stderr = 'ImportError: No module named \'flask\'';
      const result = validationMode.classifyTestResult(1, '', stderr);

      expect(result.type).toBe('missing_dependency');
      expect(result.isValidFailure).toBe(false);
    });

    it('should detect LoadError (Ruby)', () => {
      const stderr = 'LoadError: cannot load such file -- rails';
      const result = validationMode.classifyTestResult(1, '', stderr);

      expect(result.type).toBe('missing_dependency');
      expect(result.isValidFailure).toBe(false);
    });

    it('should detect Ruby LoadError with (LoadError) suffix', () => {
      // Real Ruby output format: "cannot load such file" comes BEFORE "(LoadError)"
      const stderr = `/github/workspace/spec/security_test_spec.rb:1:in \`require': cannot load such file -- rails_helper (LoadError)
\tfrom /github/workspace/spec/security_test_spec.rb:1:in \`<top (required)>'`;
      const result = validationMode.classifyTestResult(1, '', stderr);

      expect(result.type).toBe('missing_dependency');
      expect(result.isValidFailure).toBe(false);
    });
  });

  describe('Valid Test Failure Detection', () => {
    it('should classify AssertionError as valid failure', () => {
      const stderr = `
AssertionError: expected 'safe' to equal 'vulnerable'
    at Context.<anonymous> (test.js:10:14)
      `;
      const result = validationMode.classifyTestResult(1, '', stderr);

      expect(result.type).toBe('test_failed');
      expect(result.isValidFailure).toBe(true);
      expect(result.reason).toMatch(/assertion|proven/i);
    });

    it('should classify Jest/Vitest expect failures as valid', () => {
      const stdout = `
 FAIL  tests/user.test.js
  ● Security Test › should detect SQL injection

    expect(received).toBe(expected) // Object.is equality

    Expected: true
    Received: false

      at Object.<anonymous> (tests/user.test.js:15:20)
      `;
      const result = validationMode.classifyTestResult(1, stdout, '');

      expect(result.type).toBe('test_failed');
      expect(result.isValidFailure).toBe(true);
    });

    it('should classify "expected ... to" patterns as valid (Chai/RSpec)', () => {
      const stderr = 'expected result to be vulnerable';
      const result = validationMode.classifyTestResult(1, '', stderr);

      expect(result.type).toBe('test_failed');
      expect(result.isValidFailure).toBe(true);
    });

    it('should classify FAIL marker with exit 1 as valid failure', () => {
      const stdout = `
Test Suites: 1 failed, 0 passed, 1 total
Tests:       3 failed, 0 passed, 3 total
FAIL tests/security.test.js
      `;
      const result = validationMode.classifyTestResult(1, stdout, '');

      expect(result.type).toBe('test_failed');
      expect(result.isValidFailure).toBe(true);
    });

    it('should classify checkmark failure symbols as valid', () => {
      const stdout = '✗ should detect SQL injection (5ms)';
      const result = validationMode.classifyTestResult(1, stdout, '');

      expect(result.type).toBe('test_failed');
      expect(result.isValidFailure).toBe(true);
    });

    it('should classify "Received:" patterns as valid (Jest matcher output)', () => {
      const stdout = `
    Expected: true
    Received: false
      `;
      const result = validationMode.classifyTestResult(1, stdout, '');

      expect(result.type).toBe('test_failed');
      expect(result.isValidFailure).toBe(true);
    });
  });

  describe('Edge Cases', () => {
    it('should return unknown for exit 1 without clear pattern', () => {
      const result = validationMode.classifyTestResult(1, '', 'Some error occurred');

      expect(result.type).toBe('unknown');
      expect(result.isValidFailure).toBe(false);
      expect(result.reason).toMatch(/unknown|unclear|pattern/i);
    });

    it('should handle empty stdout and stderr', () => {
      const result = validationMode.classifyTestResult(1, '', '');

      expect(result.type).toBe('unknown');
      expect(result.isValidFailure).toBe(false);
    });

    it('should prioritize syntax errors over FAIL markers', () => {
      // If there's a syntax error AND a FAIL marker, syntax error is the real issue
      const stderr = 'SyntaxError: Unexpected token\nFAIL';
      const result = validationMode.classifyTestResult(1, '', stderr);

      expect(result.type).toBe('syntax_error');
      expect(result.isValidFailure).toBe(false);
    });

    it('should check both stdout and stderr for patterns', () => {
      const stdout = 'AssertionError: expected true to be false';
      const stderr = '';
      const result = validationMode.classifyTestResult(1, stdout, stderr);

      expect(result.type).toBe('test_failed');
      expect(result.isValidFailure).toBe(true);
    });

    it('should detect ENOENT errors as file not found', () => {
      const stderr = 'Error: ENOENT: no such file or directory, open \'config.json\'';
      const result = validationMode.classifyTestResult(1, '', stderr);

      expect(result.type).toBe('command_not_found');
      expect(result.isValidFailure).toBe(false);
    });

    it('should classify mocha "0 passing" as not a valid failure', () => {
      const result = validationMode.classifyTestResult(1, '\n  0 passing (1ms)\n\n', '');
      expect(result.isValidFailure).toBe(false);
      expect(result.type).toBe('runtime_error');
    });

    it('should classify mocha "0 passing, 1 failing" with AssertionError as VALID failure', () => {
      // Mocha output for a genuine test failure: 0 pass, 1 fail, with assertion error
      // This is NOT module-level assertions — mocha discovered and ran the test
      const stdout = `
  CWE-798 Hardcoded Credentials
    1) should detect hardcoded password in source

  0 passing (8ms)
  1 failing

  1) CWE-798 Hardcoded Credentials
       should detect hardcoded password in source:
     AssertionError [ERR_ASSERTION]: Found hardcoded password in source code
      at Context.<anonymous> (test/security/cwe-798.test.js:12:14)
      `;
      const result = validationMode.classifyTestResult(1, stdout, '');
      expect(result.isValidFailure).toBe(true);
      expect(result.type).toBe('test_failed');
    });

    it('should classify mocha "0 passing" with AssertionError but NO failing count as module-level', () => {
      // Module-level assertions: assertion runs at load time, mocha never discovers tests
      // Output has "0 passing" and AssertionError but NO "N failing" line
      const stdout = `
  0 passing (0ms)
`;
      const stderr = `
AssertionError [ERR_ASSERTION]: Found hardcoded password
    at Object.<anonymous> (test.js:5:1)
      `;
      const result = validationMode.classifyTestResult(1, stdout, stderr);
      expect(result.isValidFailure).toBe(false);
      expect(result.type).toBe('runtime_error');
      expect(result.reason).toMatch(/module-level/i);
    });

    it('should classify RSpec "0 examples, 0 failures" with error as not valid', () => {
      // RSpec output when test crashes during load (e.g., LoadError outside examples)
      const stdout = `Finished in 0.00023 seconds (files took 0.5 seconds to load)
0 examples, 0 failures, 1 error occurred outside of examples`;
      const result = validationMode.classifyTestResult(1, stdout, '');
      expect(result.isValidFailure).toBe(false);
      expect(result.type).toBe('runtime_error');
    });

    it('should classify "No test files found" as not a valid failure', () => {
      const result = validationMode.classifyTestResult(1, 'No test files found', '');
      expect(result.isValidFailure).toBe(false);
    });

    it('should NOT classify "0 passing" as invalid when real passes also present', () => {
      // Mocha output with real passes + failures should be classified as valid failure
      const stdout = '3 passing (5ms)\n1 failing\n\nAssertionError: expected safe to equal unsafe';
      const result = validationMode.classifyTestResult(1, stdout, '');
      expect(result.isValidFailure).toBe(true);
    });
  });

  describe('Framework-Specific Output', () => {
    it('should classify pytest failure output as valid', () => {
      const stdout = `
=================================== FAILURES ===================================
______________________________ test_sql_injection ______________________________

    def test_sql_injection():
        result = check_query("SELECT * FROM users WHERE id = " + user_input)
>       assert result.is_vulnerable == True
E       AssertionError: assert False == True

tests/test_security.py:15: AssertionError
=========================== short test summary info ============================
FAILED tests/test_security.py::test_sql_injection - AssertionError: assert...
      `;
      const result = validationMode.classifyTestResult(1, stdout, '');

      expect(result.type).toBe('test_failed');
      expect(result.isValidFailure).toBe(true);
    });

    it('should classify RSpec failure output as valid', () => {
      const stdout = `
Failures:

  1) UsersController#index should detect SQL injection
     Failure/Error: expect(response).to be_vulnerable

       expected #<Response ...> to be vulnerable
     # ./spec/controllers/users_controller_spec.rb:25:in \`block (3 levels) in <top (required)>'

Finished in 0.5 seconds (files took 1.2 seconds to load)
1 example, 1 failure
      `;
      const result = validationMode.classifyTestResult(1, stdout, '');

      expect(result.type).toBe('test_failed');
      expect(result.isValidFailure).toBe(true);
    });

    it('should classify PHPUnit failure output as valid', () => {
      const stdout = `
PHPUnit 9.5.10 by Sebastian Bergmann and contributors.

F                                                                   1 / 1 (100%)

Time: 00:00.015, Memory: 4.00 MB

There was 1 failure:

1) Tests\\Security\\SQLInjectionTest::testDetection
Failed asserting that false is true.

/var/www/tests/Security/SQLInjectionTest.php:25

FAILURES!
Tests: 1, Assertions: 1, Failures: 1.
      `;
      const result = validationMode.classifyTestResult(1, stdout, '');

      expect(result.type).toBe('test_failed');
      expect(result.isValidFailure).toBe(true);
    });

    it('should classify JUnit failure output as valid', () => {
      const stdout = `
[ERROR] Tests run: 1, Failures: 1, Errors: 0, Skipped: 0

[ERROR] testSQLInjectionDetection(com.example.SecurityTest)  Time elapsed: 0.015 s  <<< FAILURE!
java.lang.AssertionError: expected:<true> but was:<false>
    at org.junit.Assert.fail(Assert.java:88)
      `;
      const result = validationMode.classifyTestResult(1, stdout, '');

      expect(result.type).toBe('test_failed');
      expect(result.isValidFailure).toBe(true);
    });

    it('should classify ExUnit failure output as valid', () => {
      const stdout = `
  1) test detects SQL injection (RsolvTest.SecurityTest)
     test/rsolv/security_test.exs:15
     Assertion with == failed
     code:  assert is_vulnerable?(query) == true
     left:  false
     right: true

Finished in 0.1 seconds
1 test, 1 failure
      `;
      const result = validationMode.classifyTestResult(1, stdout, '');

      expect(result.type).toBe('test_failed');
      expect(result.isValidFailure).toBe(true);
    });
  });
});

describe('parseTestOutputCounts', () => {
  it('should parse mocha output with passing and failing', () => {
    const output = '  3 passing (5ms)\n  1 failing\n';
    const counts = parseTestOutputCounts(output);
    expect(counts).toEqual({ passed: 3, failed: 1, total: 4 });
  });

  it('should parse mocha output with only passing', () => {
    const output = '  5 passing (10ms)\n';
    const counts = parseTestOutputCounts(output);
    expect(counts).toEqual({ passed: 5, failed: 0, total: 5 });
  });

  it('should parse mocha "0 passing" output', () => {
    const output = '\n  0 passing (1ms)\n\n';
    const counts = parseTestOutputCounts(output);
    expect(counts).toEqual({ passed: 0, failed: 0, total: 0 });
  });

  it('should parse Jest/Vitest output', () => {
    const output = 'Tests:  2 failed, 3 passed, 5 total';
    const counts = parseTestOutputCounts(output);
    expect(counts).toEqual({ passed: 3, failed: 2, total: 5 });
  });

  it('should parse RSpec output', () => {
    const output = '10 examples, 2 failures';
    const counts = parseTestOutputCounts(output);
    expect(counts).toEqual({ passed: 8, failed: 2, total: 10 });
  });

  it('should return zeros for unparseable output', () => {
    const counts = parseTestOutputCounts('some random output');
    expect(counts).toEqual({ passed: 0, failed: 0, total: 0 });
  });
});
