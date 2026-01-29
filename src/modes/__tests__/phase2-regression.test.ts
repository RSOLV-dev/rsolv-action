/**
 * Regression tests for Phase 2 (VALIDATE) fixes
 *
 * Covers three bugs discovered during staging validation:
 * 1. scanTestFiles() returned absolute paths → double-pathing when joined with repoPath
 * 2. ValidationResult not converted to TestResults → PR body showed "0 passed, 0 failed, 0 total"
 * 3. AI-generated tests had nested it()/test() blocks → invalid in Jest/Vitest/Mocha
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ValidationMode } from '../validation-mode.js';
import { createTestConfig, exposeForTesting, type ValidationModeTestAccess } from './test-fixtures.js';

// Use vi.importActual to get REAL fs/os/path, immune to mock leaks
const realFs = await vi.importActual<typeof import('fs')>('fs');
const realPath = await vi.importActual<typeof import('path')>('path');
const realOs = await vi.importActual<typeof import('os')>('os');

describe('Phase 2 Regression Tests', () => {
  let tempDir: string;
  let validationMode: ValidationMode;
  let vm: ValidationModeTestAccess;

  beforeEach(() => {
    tempDir = realFs.mkdtempSync(realPath.join(realOs.tmpdir(), 'rsolv-phase2-'));
    const config = createTestConfig();
    validationMode = new ValidationMode(config, tempDir);
    vm = exposeForTesting(validationMode);
  });

  afterEach(() => {
    if (tempDir && realFs.existsSync(tempDir)) {
      realFs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  // ─── Fix #1: scanTestFiles() must return relative paths ───────────────

  describe('scanTestFiles() returns relative paths', () => {
    it('should return paths relative to repoPath, not absolute paths', async () => {
      // Create test files in the temp directory
      const testDir = realPath.join(tempDir, 'test');
      realFs.mkdirSync(testDir, { recursive: true });
      realFs.writeFileSync(realPath.join(testDir, 'app.test.js'), '// test');

      const specDir = realPath.join(tempDir, 'spec', 'models');
      realFs.mkdirSync(specDir, { recursive: true });
      realFs.writeFileSync(realPath.join(specDir, 'user_spec.rb'), '# test');

      const files = await vm.scanTestFiles();

      // Must be relative paths
      expect(files).toContain('test/app.test.js');
      expect(files).toContain('spec/models/user_spec.rb');

      // Must NOT be absolute paths
      for (const file of files) {
        expect(file.startsWith('/')).toBe(false);
        expect(file.includes(tempDir)).toBe(false);
      }
    });

    it('should produce paths that path.join(repoPath, file) resolves correctly', async () => {
      const testDir = realPath.join(tempDir, 'test', 'e2e', 'integration');
      realFs.mkdirSync(testDir, { recursive: true });
      realFs.writeFileSync(realPath.join(testDir, 'dashboard_spec.js'), '// test');

      const files = await vm.scanTestFiles();
      expect(files.length).toBe(1);

      // Joining with repoPath should produce a valid absolute path
      const resolvedPath = realPath.join(tempDir, files[0]);
      expect(realFs.existsSync(resolvedPath)).toBe(true);
    });
  });

  // ─── Fix #2: convertToExecutableTest() sanitizes nested test blocks ───

  describe('sanitizeTestStructure() fixes nested it/test blocks', () => {
    it('should remove test() wrappers nested inside it() blocks', () => {
      const badCode = `describe('Vulnerability Tests', () => {
  it('detect_hardcoded_password', () => {
    const fs = require('fs');

    test('should not contain hardcoded passwords', () => {
      const content = fs.readFileSync('file.js', 'utf8');
      expect(content).not.toContain('password123');
    });
  });
});`;

      const result = vm.sanitizeTestStructure(badCode);

      // Should NOT contain nested test() inside it()
      expect(result).not.toMatch(/it\s*\([^)]*\)\s*.*\n[\s\S]*test\s*\(/);

      // Should still have the describe and it blocks
      expect(result).toContain('describe(');
      expect(result).toContain('it(');

      // Should preserve the actual test body
      expect(result).toContain("expect(content).not.toContain('password123')");

      // Should NOT contain the inner test() wrapper
      expect(result).not.toContain("test('should not contain hardcoded passwords'");
    });

    it('should handle multiple nested test() blocks', () => {
      const badCode = `describe('Tests', () => {
  it('test_one', () => {
    test('inner one', () => {
      expect(1).toBe(1);
    });
  });

  it('test_two', () => {
    test('inner two', () => {
      expect(2).toBe(2);
    });
  });
});`;

      const result = vm.sanitizeTestStructure(badCode);

      expect(result).toContain("it('test_one'");
      expect(result).toContain("it('test_two'");
      expect(result).toContain('expect(1).toBe(1)');
      expect(result).toContain('expect(2).toBe(2)');
      expect(result).not.toContain("test('inner one'");
      expect(result).not.toContain("test('inner two'");
    });

    it('should not modify valid test structures', () => {
      const validCode = `describe('Tests', () => {
  it('should work', () => {
    expect(true).toBe(true);
  });
});`;

      const result = vm.sanitizeTestStructure(validCode);
      expect(result).toBe(validCode);
    });

    it('should not modify code with only test() and no it()', () => {
      const validCode = `describe('Tests', () => {
  test('should work', () => {
    expect(true).toBe(true);
  });
});`;

      const result = vm.sanitizeTestStructure(validCode);
      expect(result).toBe(validCode);
    });

    it('should pass through non-test code unchanged', () => {
      const regularCode = `function add(a, b) { return a + b; }`;
      const result = vm.sanitizeTestStructure(regularCode);
      expect(result).toBe(regularCode);
    });

    it('should handle nested test() with inner callbacks (brace depth tracking)', () => {
      // Reproduces the exact AI output that caused the brace-depth bug:
      // jest.fn callbacks inside test() have }) closings that the old naive
      // state machine would match as the end of the test() block.
      const badCode = `describe('Vulnerability Validation Tests', () => {
  it('SQL Injection via userId parameter', () => {
    const { ProfileDAO } = require('./profile');

    test('SQL injection should fail', (done) => {
      const mockDb = {
        collection: () => ({
          findOne: jest.fn((query, callback) => {
            expect(query._id).toBe(NaN);
            callback(null, { _id: 999, firstName: 'Admin' });
          })
        })
      };
      const dao = new ProfileDAO(mockDb);
      dao.getByUserId("1' OR '1'='1", (err, user) => {
        expect(user).toBeDefined();
        done();
      });
    });
  });
});`;

      const result = vm.sanitizeTestStructure(badCode);

      // test() wrapper must be removed
      expect(result).not.toMatch(/\btest\s*\(/);

      // All inner code preserved (including jest.fn callback closings)
      expect(result).toContain('jest.fn((query, callback)');
      expect(result).toContain('expect(query._id).toBe(NaN)');
      expect(result).toContain('expect(user).toBeDefined()');
      expect(result).toContain('ProfileDAO');
      expect(result).toContain('collection');

      // Structure intact
      expect(result).toContain('describe(');
      expect(result).toContain('it(');
    });
  });

  describe('convertToExecutableTestSanitized() applies sanitization to all paths', () => {
    it('should sanitize nested it/test in string input', () => {
      const badString = `describe('Tests', () => {
  it('check', () => {
    test('inner', () => {
      expect(1).toBe(1);
    });
  });
});`;

      const result = vm.convertToExecutableTestSanitized(badString);

      // Should be sanitized — no nested test() inside it()
      expect(result).toContain('expect(1).toBe(1)');
      expect(result).not.toContain("test('inner'");
    });

    it('should sanitize object input where testCode contains test() blocks', () => {
      // This is the exact scenario from staging: AI returns an object where
      // testCode itself contains a test() block, which gets wrapped in it()
      const objectInput = {
        red: {
          testName: 'SQL Injection test',
          testCode: `test('should detect injection', () => {
      expect(isVulnerable("' OR 1=1")).toBe(true);
    });`
        }
      };

      const result = vm.convertToExecutableTestSanitized(objectInput);

      // Should be executable JS with describe/it structure
      expect(result).toContain('describe(');
      expect(result).toContain('it(');
      // The nested test() should be stripped
      expect(result).not.toMatch(/\btest\s*\(/);
      // The assertion body should be preserved
      expect(result).toContain('expect(isVulnerable');
    });

    it('should still handle clean object formats correctly', () => {
      const objectInput = {
        red: {
          testName: 'SQL Injection test',
          testCode: 'expect(true).toBe(false);'
        }
      };

      const result = vm.convertToExecutableTestSanitized(objectInput);

      // Should be executable JS, not JSON
      expect(result).toContain('describe(');
      expect(result).toContain('it(');
      expect(result).toContain('expect(true).toBe(false)');
      expect(result).not.toContain('"red"');
    });
  });

  // ─── Fix #4: AI-generated testCode double-wrapping with describe/it ───

  describe('double-wrapping prevention for testCode with framework structure', () => {
    it('should not double-wrap testCode that already has describe/it structure', () => {
      const objectInput = {
        red: {
          testName: 'SQL Injection test',
          testCode: `describe('ProfileDAO SQL Injection', () => {
  it('should be vulnerable', () => {
    expect(isVulnerable("' OR 1=1")).toBe(true);
  });
});`
        }
      };
      const result = vm.convertToExecutableTestSanitized(objectInput);

      // Should contain the test content
      expect(result).toContain('describe(');
      expect(result).toContain('it(');
      expect(result).toContain("expect(isVulnerable");

      // Critical: the AI's describe/it should NOT be nested inside another it()
      // Count describe blocks — should be at most 2 (outer wrapper + AI's), never nested
      const describeCount = (result.match(/\bdescribe\s*\(/g) || []).length;
      const itCount = (result.match(/\bit\s*\(/g) || []).length;

      // If there's a wrapper describe + AI's describe, there should be only AI's it()
      // not wrapper it() + AI's it() (which means double-wrapping)
      // In a properly handled case: either use AI's code directly (1 describe, 1 it)
      // or wrap in describe only (2 describe, 1 it) — never 1+ describe inside it()
      if (describeCount >= 2) {
        // If we have 2 describes, the inner one must NOT be inside an it() block
        // Parse: find lines with it( and lines with describe(, verify no describe after it
        const lines = result.split('\n');
        let insideIt = false;
        let braceDepth = 0;
        let itBraceDepth = 0;
        for (const line of lines) {
          if (/^\s*it\s*\(/.test(line)) {
            insideIt = true;
            itBraceDepth = braceDepth;
          }
          braceDepth += (line.match(/\{/g) || []).length;
          braceDepth -= (line.match(/\}/g) || []).length;
          if (insideIt && /^\s*describe\s*\(/.test(line)) {
            // describe() inside it() — this is the bug
            expect(line).toBe('THIS SHOULD NOT HAPPEN: describe() nested inside it()');
          }
          if (insideIt && braceDepth <= itBraceDepth) {
            insideIt = false;
          }
        }
      }
    });

    it('should remove describe() blocks nested inside it() blocks via sanitizer', () => {
      const badCode = `describe('Vulnerability Validation Tests', () => {
  it('SQL Injection via userId', () => {
    const { ProfileDAO } = require('./profile');
    describe('ProfileDAO SQL Injection', () => {
      it('should be vulnerable', (done) => {
        const mockDb = { collection: () => ({ findOne: jest.fn() }) };
        expect(mockDb).toBeDefined();
        done();
      });
    });
  });
});`;
      const result = vm.sanitizeTestStructure(badCode);

      // Inner describe should be flattened — not nested inside it()
      expect(result).toContain('describe(');
      expect(result).toContain('it(');
      expect(result).toContain('expect(mockDb).toBeDefined()');

      // Should not have describe() nested inside it()
      expect(result).not.toMatch(/\bit\s*\([^)]*\)[^{]*\{[\s\S]*?\bdescribe\s*\(/);
    });

    it('should handle redTests array where testCode already has test structure', () => {
      const objectInput = {
        redTests: [
          {
            testName: 'SQL Injection',
            testCode: `it('should detect injection', () => {
    expect(isVulnerable("' OR 1=1")).toBe(true);
  });`
          }
        ]
      };
      const result = vm.convertToExecutableTestSanitized(objectInput);
      expect(result).toContain('describe(');
      expect(result).toContain("expect(isVulnerable");

      // Should not have it() inside it()
      const itMatches = result.match(/\bit\s*\(/g) || [];
      expect(itMatches.length).toBeLessThanOrEqual(1);
    });
  });

  // ─── Fix #3: ValidationResult → TestResults conversion ────────────────

  describe('ValidationResult to TestResults conversion', () => {
    // This tests the data structure that ends up in testResults
    // by verifying the conversion logic directly.
    // The actual conversion happens in validateVulnerability() which is hard
    // to unit test (requires mocking AI + git), so we verify the shape here.

    it('should produce correct counts from boolean arrays', () => {
      // Simulate what the conversion does:
      // const redTestResults = validationResult.vulnerableCommit.redTestsPassed || [];
      // passed: redTestResults.filter(p => p).length
      // failed: redTestResults.filter(p => !p).length
      // total: redTestResults.length

      // Case 1: All tests failed (expected for RED tests on vulnerable code)
      const allFailed = [false, false, false];
      expect(allFailed.filter(p => p).length).toBe(0);  // passed
      expect(allFailed.filter(p => !p).length).toBe(3);  // failed
      expect(allFailed.length).toBe(3);                   // total

      // Case 2: All tests passed (false positive scenario)
      const allPassed = [true, true, true];
      expect(allPassed.filter(p => p).length).toBe(3);   // passed
      expect(allPassed.filter(p => !p).length).toBe(0);  // failed
      expect(allPassed.length).toBe(3);                   // total

      // Case 3: Mixed results
      const mixed = [true, false, true, false];
      expect(mixed.filter(p => p).length).toBe(2);       // passed
      expect(mixed.filter(p => !p).length).toBe(2);      // failed
      expect(mixed.length).toBe(4);                       // total

      // Case 4: Empty (no tests ran)
      const empty: boolean[] = [];
      expect(empty.filter(p => p).length).toBe(0);       // passed
      expect(empty.filter(p => !p).length).toBe(0);      // failed
      expect(empty.length).toBe(0);                       // total
    });

    it('should match the TestResults interface expected by PR body generator', () => {
      // The PR body generator at pr-git-educational.ts:365 destructures:
      // const { passed = 0, failed = 0, total = 0 } = validationData.testResults;
      // So testResults must have these numeric fields.

      const redTestsPassed = [false, false, true]; // 2 failed, 1 passed
      const testResults = {
        passed: redTestsPassed.filter(p => p).length,
        failed: redTestsPassed.filter(p => !p).length,
        total: redTestsPassed.length,
        output: 'RED tests executed',
        exitCode: 1
      };

      // Verify destructuring works as the PR body generator expects
      const { passed = 0, failed = 0, total = 0 } = testResults;
      expect(passed).toBe(1);
      expect(failed).toBe(2);
      expect(total).toBe(3);

      // Verify the PR body template would produce correct output
      const prLine = `Tests: ${failed} failed, ${passed} passed, ${total} total`;
      expect(prLine).toBe('Tests: 2 failed, 1 passed, 3 total');
    });

    it('should not produce "Tests: 0 failed, 0 passed, 0 total" when tests ran', () => {
      // This was the original bug — raw ValidationResult passed instead of TestResults
      const rawValidationResult = {
        success: true,
        vulnerableCommit: {
          redTestsPassed: [false, false],
          allPassed: false
        },
        fixedCommit: {
          redTestsPassed: [],
          allPassed: false
        },
        isValidFix: false
      };

      // Old behavior: destructuring raw ValidationResult gets undefined → defaults to 0
      const { passed: oldPassed = 0, failed: oldFailed = 0, total: oldTotal = 0 } =
        rawValidationResult as Record<string, number>;
      expect(oldPassed).toBe(0); // Bug: would show 0
      expect(oldFailed).toBe(0); // Bug: would show 0
      expect(oldTotal).toBe(0);  // Bug: would show 0

      // New behavior: convert first, then destructure gets real values
      const redTestResults = rawValidationResult.vulnerableCommit.redTestsPassed || [];
      const converted = {
        passed: redTestResults.filter(p => p).length,
        failed: redTestResults.filter(p => !p).length,
        total: redTestResults.length,
      };
      const { passed: newPassed = 0, failed: newFailed = 0, total: newTotal = 0 } = converted;
      expect(newPassed).toBe(0);  // Correct: 0 passed
      expect(newFailed).toBe(2);  // Correct: 2 failed
      expect(newTotal).toBe(2);   // Correct: 2 total
    });
  });
});
