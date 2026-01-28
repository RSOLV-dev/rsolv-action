/**
 * Test suite for scanTestFiles() pattern coverage
 *
 * RFC-060-AMENDMENT-001: Tests scan patterns against REAL filesystem
 * to ensure we find test files with various naming conventions.
 *
 * These tests use REAL temp directories (not mocked 'find' command)
 * because mocking hid the pattern mismatch bugs discovered during
 * demo validation.
 *
 * IMPORTANT: This file explicitly uses vi.importActual for fs/os/path
 * to prevent mock interference from other test files sharing the same
 * vitest fork (singleFork: true in config).
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ValidationMode } from '../validation-mode.js';
import { createTestConfig, exposeForTesting, type ValidationModeTestAccess } from './test-fixtures.js';

// Use vi.importActual to get REAL fs/os/path, immune to mock leaks
// from other test files in the same shard/fork
const realFs = await vi.importActual<typeof import('fs')>('fs');
const realPath = await vi.importActual<typeof import('path')>('path');
const realOs = await vi.importActual<typeof import('os')>('os');

describe('scanTestFiles() Pattern Coverage', () => {
  let tempDir: string;
  let vm: ValidationModeTestAccess;

  beforeEach(() => {
    // Create a real temp directory for each test
    tempDir = realFs.mkdtempSync(realPath.join(realOs.tmpdir(), 'rsolv-test-'));

    // Create ValidationMode with the temp dir as repoPath
    const config = createTestConfig();
    const validationMode = new ValidationMode(config);
    vm = exposeForTesting(validationMode);
    vm.repoPath = tempDir;
  });

  afterEach(() => {
    // Clean up temp directory
    if (tempDir && realFs.existsSync(tempDir)) {
      realFs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  /**
   * Helper to create test files in the temp directory
   */
  function createTestFile(relativePath: string, content: string = '// test file'): string {
    const fullPath = realPath.join(tempDir, relativePath);
    realFs.mkdirSync(realPath.dirname(fullPath), { recursive: true });
    realFs.writeFileSync(fullPath, content);
    return fullPath;
  }

  describe('JavaScript/TypeScript patterns', () => {
    it('should find *.spec.ts files', async () => {
      createTestFile('src/user.spec.ts');
      createTestFile('src/auth.spec.ts');

      const files = await vm.scanTestFiles();

      expect(files).toContain(realPath.join(tempDir, 'src/user.spec.ts'));
      expect(files).toContain(realPath.join(tempDir, 'src/auth.spec.ts'));
    });

    it('should find *.test.ts files', async () => {
      createTestFile('src/utils.test.ts');

      const files = await vm.scanTestFiles();

      expect(files).toContain(realPath.join(tempDir, 'src/utils.test.ts'));
    });

    it('should find *.spec.js files', async () => {
      createTestFile('lib/helpers.spec.js');

      const files = await vm.scanTestFiles();

      expect(files).toContain(realPath.join(tempDir, 'lib/helpers.spec.js'));
    });

    it('should find *.test.js files', async () => {
      createTestFile('lib/utils.test.js');

      const files = await vm.scanTestFiles();

      expect(files).toContain(realPath.join(tempDir, 'lib/utils.test.js'));
    });

    it('should find *_spec.js files (Jasmine convention)', async () => {
      createTestFile('spec/UserSpec.js');
      createTestFile('spec/auth_spec.js');

      const files = await vm.scanTestFiles();

      // These use underscore convention common in Jasmine
      expect(files.some((f: string) => f.includes('_spec.js'))).toBe(true);
    });

    it('should find *.spec.tsx files (React)', async () => {
      createTestFile('components/Button.spec.tsx');

      const files = await vm.scanTestFiles();

      expect(files).toContain(realPath.join(tempDir, 'components/Button.spec.tsx'));
    });

    it('should find *.test.tsx files (React)', async () => {
      createTestFile('components/Form.test.tsx');

      const files = await vm.scanTestFiles();

      expect(files).toContain(realPath.join(tempDir, 'components/Form.test.tsx'));
    });

    it('should find files in __tests__ directories', async () => {
      createTestFile('src/__tests__/index.test.ts');

      const files = await vm.scanTestFiles();

      expect(files).toContain(realPath.join(tempDir, 'src/__tests__/index.test.ts'));
    });
  });

  describe('Ruby patterns', () => {
    it('should find *_spec.rb files (RSpec)', async () => {
      createTestFile('spec/controllers/users_controller_spec.rb');
      createTestFile('spec/models/user_spec.rb');

      const files = await vm.scanTestFiles();

      expect(files).toContain(realPath.join(tempDir, 'spec/controllers/users_controller_spec.rb'));
      expect(files).toContain(realPath.join(tempDir, 'spec/models/user_spec.rb'));
    });

    it('should find *_test.rb files (Minitest)', async () => {
      createTestFile('test/models/user_test.rb');
      createTestFile('test/controllers/users_controller_test.rb');

      const files = await vm.scanTestFiles();

      expect(files).toContain(realPath.join(tempDir, 'test/models/user_test.rb'));
      expect(files).toContain(realPath.join(tempDir, 'test/controllers/users_controller_test.rb'));
    });

    it('should find test_*.rb files (Minitest prefix convention)', async () => {
      createTestFile('test/test_user.rb');
      createTestFile('test/test_authentication.rb');

      const files = await vm.scanTestFiles();

      expect(files.some((f: string) => f.includes('test_user.rb'))).toBe(true);
      expect(files.some((f: string) => f.includes('test_authentication.rb'))).toBe(true);
    });
  });

  describe('Python patterns', () => {
    it('should find *_test.py files', async () => {
      createTestFile('tests/user_test.py');
      createTestFile('tests/auth_test.py');

      const files = await vm.scanTestFiles();

      expect(files).toContain(realPath.join(tempDir, 'tests/user_test.py'));
      expect(files).toContain(realPath.join(tempDir, 'tests/auth_test.py'));
    });

    it('should find test_*.py files (pytest prefix convention)', async () => {
      createTestFile('tests/test_user.py');
      createTestFile('tests/test_authentication.py');

      const files = await vm.scanTestFiles();

      expect(files.some((f: string) => f.includes('test_user.py'))).toBe(true);
      expect(files.some((f: string) => f.includes('test_authentication.py'))).toBe(true);
    });
  });

  describe('Java patterns', () => {
    it('should find *Test.java files', async () => {
      createTestFile('src/test/java/com/example/UserTest.java');

      const files = await vm.scanTestFiles();

      expect(files).toContain(realPath.join(tempDir, 'src/test/java/com/example/UserTest.java'));
    });

    it('should find *Tests.java files (plural convention)', async () => {
      createTestFile('src/test/java/com/example/UserTests.java');

      const files = await vm.scanTestFiles();

      expect(files.some((f: string) => f.includes('UserTests.java'))).toBe(true);
    });

    it('should find Test*.java files (prefix convention)', async () => {
      createTestFile('src/test/java/com/example/TestUser.java');

      const files = await vm.scanTestFiles();

      expect(files.some((f: string) => f.includes('TestUser.java'))).toBe(true);
    });

    it('should find *Spec.java files (BDD convention)', async () => {
      createTestFile('src/test/java/com/example/UserSpec.java');

      const files = await vm.scanTestFiles();

      expect(files.some((f: string) => f.includes('UserSpec.java'))).toBe(true);
    });
  });

  describe('PHP patterns', () => {
    it('should find *Test.php files (PHPUnit)', async () => {
      createTestFile('tests/Unit/UserTest.php');
      createTestFile('tests/Feature/AuthTest.php');

      const files = await vm.scanTestFiles();

      expect(files).toContain(realPath.join(tempDir, 'tests/Unit/UserTest.php'));
      expect(files).toContain(realPath.join(tempDir, 'tests/Feature/AuthTest.php'));
    });

    it('should find *_test.php files (underscore convention)', async () => {
      createTestFile('tests/user_test.php');

      const files = await vm.scanTestFiles();

      expect(files.some((f: string) => f.includes('user_test.php'))).toBe(true);
    });
  });

  describe('Elixir patterns', () => {
    it('should find *_test.exs files', async () => {
      createTestFile('test/rsolv/user_test.exs');
      createTestFile('test/rsolv_web/controllers/user_controller_test.exs');

      const files = await vm.scanTestFiles();

      expect(files).toContain(realPath.join(tempDir, 'test/rsolv/user_test.exs'));
      expect(files).toContain(realPath.join(tempDir, 'test/rsolv_web/controllers/user_controller_test.exs'));
    });
  });

  describe('Edge cases', () => {
    it('should return empty array for repo with no test files', async () => {
      // Just create some non-test files
      createTestFile('src/index.ts', 'export default {}');
      createTestFile('lib/utils.js', 'module.exports = {}');

      const files = await vm.scanTestFiles();

      expect(files).toEqual([]);
    });

    it('should not throw when repo is empty', async () => {
      // tempDir is empty
      const files = await vm.scanTestFiles();

      expect(Array.isArray(files)).toBe(true);
      expect(files).toEqual([]);
    });

    it('should exclude node_modules directory', async () => {
      createTestFile('node_modules/some-lib/test.spec.js');
      createTestFile('src/app.test.ts');

      const files = await vm.scanTestFiles();

      // Should NOT include files from node_modules
      expect(files.every((f: string) => !f.includes('node_modules'))).toBe(true);
      // Should include files from src
      expect(files.some((f: string) => f.includes('app.test.ts'))).toBe(true);
    });

    it('should exclude vendor directory', async () => {
      createTestFile('vendor/bundle/gems/rspec/spec/test_spec.rb');
      createTestFile('spec/models/user_spec.rb');

      const files = await vm.scanTestFiles();

      // Should NOT include files from vendor
      expect(files.every((f: string) => !f.includes('vendor'))).toBe(true);
      // Should include files from spec
      expect(files.some((f: string) => f.includes('user_spec.rb'))).toBe(true);
    });
  });

  describe('Mixed language repository', () => {
    it('should find test files across multiple languages', async () => {
      // JavaScript
      createTestFile('frontend/src/app.test.ts');
      // Ruby
      createTestFile('spec/models/user_spec.rb');
      // Python
      createTestFile('scripts/tests/test_utils.py');
      // PHP
      createTestFile('api/tests/UserTest.php');

      const files = await vm.scanTestFiles();

      expect(files.length).toBeGreaterThanOrEqual(4);
      expect(files.some((f: string) => f.includes('.test.ts'))).toBe(true);
      expect(files.some((f: string) => f.includes('_spec.rb'))).toBe(true);
      expect(files.some((f: string) => f.includes('test_utils.py'))).toBe(true);
      expect(files.some((f: string) => f.includes('UserTest.php'))).toBe(true);
    });
  });
});
