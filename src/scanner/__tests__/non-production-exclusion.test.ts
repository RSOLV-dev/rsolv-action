/**
 * TDD test: Verify non-production files are excluded from vulnerability scanning.
 *
 * Bug: The scanner scanned all code files including test files, artifact scripts,
 * and build configs. This caused false positives from non-production code like
 * artifacts/db-reset.js being flagged for SQL injection.
 */

import { describe, it, expect } from 'vitest';
import { RepositoryScanner } from '../repository-scanner.js';

describe('RepositoryScanner non-production file exclusion', () => {
  const check = RepositoryScanner.isNonProductionFile;

  describe('test directories', () => {
    it('should skip files in test/ directory', () => {
      expect(check('test/unit/auth.test.js')).toBe(true);
    });

    it('should skip files in tests/ directory', () => {
      expect(check('tests/integration/api.js')).toBe(true);
    });

    it('should skip files in __tests__/ directory', () => {
      expect(check('src/__tests__/helper.ts')).toBe(true);
    });

    it('should skip files in spec/ directory', () => {
      expect(check('spec/models/user_spec.rb')).toBe(true);
    });

    it('should skip files in __mocks__/ directory', () => {
      expect(check('src/__mocks__/api.ts')).toBe(true);
    });

    it('should skip files in fixtures/ directory', () => {
      expect(check('test/fixtures/vulnerable-code.js')).toBe(true);
    });
  });

  describe('artifact directories', () => {
    it('should skip files in artifacts/ directory', () => {
      expect(check('artifacts/db-reset.js')).toBe(true);
    });

    it('should skip nested artifact files', () => {
      expect(check('build/artifacts/setup.js')).toBe(true);
    });
  });

  describe('test file patterns', () => {
    it('should skip .test.js files', () => {
      expect(check('src/auth.test.js')).toBe(true);
    });

    it('should skip .spec.ts files', () => {
      expect(check('src/auth.spec.ts')).toBe(true);
    });

    it('should skip _test.py files', () => {
      expect(check('app/auth_test.py')).toBe(true);
    });

    it('should skip _spec.rb files', () => {
      expect(check('app/models/user_spec.rb')).toBe(true);
    });
  });

  describe('build config files', () => {
    it('should skip Gruntfile.js', () => {
      expect(check('Gruntfile.js')).toBe(true);
    });

    it('should skip Gulpfile.js', () => {
      expect(check('Gulpfile.js')).toBe(true);
    });

    it('should skip Rakefile', () => {
      expect(check('Rakefile')).toBe(true);
    });
  });

  describe('production files should NOT be excluded', () => {
    it('should not skip app/routes/contributions.js', () => {
      expect(check('app/routes/contributions.js')).toBe(false);
    });

    it('should not skip src/controllers/user.ts', () => {
      expect(check('src/controllers/user.ts')).toBe(false);
    });

    it('should not skip lib/database.py', () => {
      expect(check('lib/database.py')).toBe(false);
    });

    it('should not skip app/models/user.rb', () => {
      expect(check('app/models/user.rb')).toBe(false);
    });

    it('should not skip server/index.js', () => {
      expect(check('server/index.js')).toBe(false);
    });

    it('should not skip views/profile.ejs', () => {
      expect(check('views/profile.ejs')).toBe(false);
    });
  });

  describe('edge cases', () => {
    it('should handle Windows-style paths', () => {
      expect(check('test\\unit\\auth.test.js')).toBe(true);
    });

    it('should not flag "test" as substring in production paths', () => {
      // "contest" contains "test" but is not a test directory
      expect(check('app/contest/results.js')).toBe(false);
    });

    it('should not flag "testing" directory (testing is a valid app name)', () => {
      // Only exact directory matches, not partial
      expect(check('app/testing-service/index.js')).toBe(false);
    });
  });
});
