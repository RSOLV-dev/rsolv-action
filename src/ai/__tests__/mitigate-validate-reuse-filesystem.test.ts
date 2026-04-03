/**
 * MITIGATE RED test reuse — filesystem integration test
 *
 * Uses real filesystem operations (temp dir with git repo) to verify
 * the full verifyFixWithValidateRedTest flow end-to-end. Requires
 * pytest to be installed for the Python ecosystem tests.
 *
 * This test creates actual git repos, commits, and runs real test
 * commands — it's NOT a mock-based unit test.
 */

// Unmock child_process and fs — this test needs real filesystem operations
// (the global vitest-setup.ts mocks child_process to prevent subprocess spawning)
import { vi } from 'vitest';
vi.unmock('child_process');
vi.unmock('fs');

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execSync } from 'child_process';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import {
  extractValidateRedTest,
  verifyFixWithValidateRedTest,
  runRedTestForVerification,
  type ValidateRedTest,
} from '../validate-test-reuse.js';

// Check if pytest is available
let hasPytest = false;
try {
  execSync('python3 -m pytest --version', { stdio: 'pipe' });
  hasPytest = true;
} catch {
  try {
    execSync('pytest --version', { stdio: 'pipe' });
    hasPytest = true;
  } catch {
    hasPytest = false;
  }
}

describe.skipIf(!hasPytest)('MITIGATE RED test reuse (filesystem)', () => {
  let tempDir: string;
  let vulnerableCommit: string;

  beforeEach(() => {
    // Create temp directory with a git repo
    tempDir = mkdtempSync(join(tmpdir(), 'rsolv-mitigate-test-'));

    // Initialize git repo
    execSync('git init', { cwd: tempDir, stdio: 'pipe' });
    execSync('git config user.email "test@rsolv.dev"', { cwd: tempDir, stdio: 'pipe' });
    execSync('git config user.name "RSOLV Test"', { cwd: tempDir, stdio: 'pipe' });

    // Create a "vulnerable" Python file with hardcoded secret
    const vulnerableCode = `
import os

# Hardcoded secret - CWE-798
API_KEY = "sk-hardcoded-secret-key-12345"

def get_api_key():
    return API_KEY

def make_request():
    key = get_api_key()
    return f"Using key: {key}"
`;
    writeFileSync(join(tempDir, 'app.py'), vulnerableCode);

    // Create tests directory
    mkdirSync(join(tempDir, 'tests'), { recursive: true });

    // Commit vulnerable code
    execSync('git add -A && git commit -m "initial vulnerable code"', {
      cwd: tempDir,
      stdio: 'pipe',
    });
    vulnerableCommit = execSync('git rev-parse HEAD', {
      cwd: tempDir,
      encoding: 'utf-8',
    }).trim();
  });

  afterEach(() => {
    // Clean up temp directory
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  it('verifies Python fix with pytest RED test', () => {
    // Create the RED test that detects hardcoded secrets
    const redTestCode = `
import importlib
import sys
import os

def test_no_hardcoded_api_key():
    """RED test: API key should come from environment, not be hardcoded."""
    # Reload the module to pick up any changes
    if 'app' in sys.modules:
        del sys.modules['app']

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import app

    # The API key should NOT be a hardcoded string
    key = app.get_api_key()
    assert key != "sk-hardcoded-secret-key-12345", (
        "API key is hardcoded! Should use environment variable instead."
    )
`;

    const redTest: ValidateRedTest = {
      testCode: redTestCode,
      testFile: 'tests/test_vulnerability_validation.py',
      framework: 'pytest',
      branchName: 'rsolv/validate/issue-1',
    };

    // Apply fix: replace hardcoded secret with env var
    const fixedCode = `
import os

def get_api_key():
    return os.environ.get("API_KEY", "")

def make_request():
    key = get_api_key()
    return f"Using key: {key}"
`;
    writeFileSync(join(tempDir, 'app.py'), fixedCode);
    execSync('git add -A && git commit -m "fix: use env var for API key"', {
      cwd: tempDir,
      stdio: 'pipe',
    });
    const fixedCommit = execSync('git rev-parse HEAD', {
      cwd: tempDir,
      encoding: 'utf-8',
    }).trim();

    // Run verification
    const resultPromise = verifyFixWithValidateRedTest(
      vulnerableCommit,
      fixedCommit,
      redTest,
      tempDir
    );

    return resultPromise.then((result) => {
      expect(result.isValidFix).toBe(true);
      expect(result.vulnerableResult.passed).toBe(false); // RED on vulnerable
      expect(result.fixedResult.passed).toBe(true); // GREEN on fixed
    });
  });

  it('rejects bad fix that does not address vulnerability', () => {
    const redTestCode = `
import importlib
import sys
import os

def test_no_hardcoded_api_key():
    """RED test: API key should come from environment, not be hardcoded."""
    if 'app' in sys.modules:
        del sys.modules['app']

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import app

    key = app.get_api_key()
    assert key != "sk-hardcoded-secret-key-12345", (
        "API key is hardcoded! Should use environment variable instead."
    )
`;

    const redTest: ValidateRedTest = {
      testCode: redTestCode,
      testFile: 'tests/test_vulnerability_validation.py',
      framework: 'pytest',
      branchName: 'rsolv/validate/issue-1',
    };

    // Apply BAD fix: rename variable but keep hardcoded value
    const badFixCode = `
import os

# Renamed variable but still hardcoded!
SECRET_API_KEY = "sk-hardcoded-secret-key-12345"

def get_api_key():
    return SECRET_API_KEY

def make_request():
    key = get_api_key()
    return f"Using key: {key}"
`;
    writeFileSync(join(tempDir, 'app.py'), badFixCode);
    execSync('git add -A && git commit -m "bad fix: rename but still hardcoded"', {
      cwd: tempDir,
      stdio: 'pipe',
    });
    const badFixCommit = execSync('git rev-parse HEAD', {
      cwd: tempDir,
      encoding: 'utf-8',
    }).trim();

    return verifyFixWithValidateRedTest(
      vulnerableCommit,
      badFixCommit,
      redTest,
      tempDir
    ).then((result) => {
      expect(result.isValidFix).toBe(false);
      expect(result.fixedResult.passed).toBe(false); // Still RED
    });
  });

  it('handles missing test framework gracefully', () => {
    const redTest: ValidateRedTest = {
      testCode: '<?php echo "test"; ?>',
      testFile: 'tests/VulnerabilityValidationTest.php',
      framework: 'phpunit',
      branchName: 'rsolv/validate/issue-1',
    };

    // phpunit is almost certainly not installed
    return runRedTestForVerification(
      '<?php echo "test"; ?>',
      'tests/VulnerabilityValidationTest.php',
      'phpunit',
      tempDir
    ).then((result) => {
      expect(result.passed).toBe(false);
      // Should be infrastructure failure (command not found) or just a failure
      // Either way, should not crash
      expect(result.exitCode).toBeGreaterThan(0);
    });
  });
});

describe('extractValidateRedTest (unit)', () => {
  it('extracts test from real-shaped validation data', () => {
    // Simulate the exact shape that comes from the platform after VALIDATE
    const validationData = {
      validation: {
        'issue-42': {
          issueNumber: 42,
          validated: true,
          branchName: 'rsolv/validate/issue-42',
          framework: 'pytest',
          redTests: {
            redTests: [
              {
                testName: 'test_sql_injection_vulnerability',
                testCode: 'def test_sql():\n    import sqlite3\n    assert False',
                attackVector: 'SQL injection via string concatenation',
                expectedBehavior: 'should_fail_on_vulnerable_code',
              },
            ],
          },
          testResults: {
            testFile: 'tests/test_vulnerability_validation.py',
            passed: false,
            output: 'FAILED tests/test_vulnerability_validation.py::test_sql',
          },
          testType: 'behavioral',
          cweId: 'CWE-89',
          retryCount: 0,
          classificationSource: 'platform',
          infrastructureFailure: false,
          validationInconclusive: false,
          timestamp: '2026-02-13T00:00:00Z',
          commitHash: 'abc123',
        },
      },
    };

    const result = extractValidateRedTest(validationData, 42);
    expect(result).not.toBeNull();
    expect(result!.testCode).toContain('sqlite3');
    expect(result!.framework).toBe('pytest');
    expect(result!.testFile).toBe('tests/test_vulnerability_validation.py');
    expect(result!.branchName).toBe('rsolv/validate/issue-42');
  });

  it('handles missing issue key gracefully', () => {
    const validationData = {
      validation: {
        'issue-99': { validated: true, framework: 'pytest' },
      },
    };

    // Looking for issue-42 but only issue-99 exists
    const result = extractValidateRedTest(validationData, 42);
    expect(result).toBeNull();
  });
});
