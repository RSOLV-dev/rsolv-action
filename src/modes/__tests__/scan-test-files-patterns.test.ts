/**
 * Test suite for scanTestFiles() pattern coverage
 *
 * RFC-060-AMENDMENT-001: Tests scan patterns against REAL filesystem
 * to ensure we find test files with various naming conventions.
 *
 * These tests validate two things:
 * 1. TEST_FILE_PATTERNS and EXCLUDED_DIRECTORIES cover all supported languages
 * 2. scanTestFiles() correctly uses these patterns on a real filesystem
 *
 * IMPORTANT: Uses vi.importActual for fs/os/path to prevent mock interference
 * from other test files sharing the same vitest fork (singleFork: true).
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { TEST_FILE_PATTERNS, EXCLUDED_DIRECTORIES, isTestFile, isExcludedDirectory } from '../../constants/test-patterns.js';

// Use vi.importActual to get REAL fs/os/path, immune to mock leaks
const realFs = await vi.importActual<typeof import('fs')>('fs');
const realPath = await vi.importActual<typeof import('path')>('path');
const realOs = await vi.importActual<typeof import('os')>('os');

describe('Test File Pattern Coverage', () => {
  describe('JavaScript/TypeScript patterns', () => {
    it('should match *.spec.ts files', () => {
      expect(isTestFile('user.spec.ts')).toBe(true);
      expect(isTestFile('auth.spec.ts')).toBe(true);
    });

    it('should match *.test.ts files', () => {
      expect(isTestFile('utils.test.ts')).toBe(true);
    });

    it('should match *.spec.js files', () => {
      expect(isTestFile('helpers.spec.js')).toBe(true);
    });

    it('should match *.test.js files', () => {
      expect(isTestFile('utils.test.js')).toBe(true);
    });

    it('should match *_spec.js files (Jasmine convention)', () => {
      expect(isTestFile('auth_spec.js')).toBe(true);
    });

    it('should match *_spec.ts files (Jasmine convention)', () => {
      expect(isTestFile('auth_spec.ts')).toBe(true);
    });

    it('should match *.spec.tsx files (React)', () => {
      expect(isTestFile('Button.spec.tsx')).toBe(true);
    });

    it('should match *.test.tsx files (React)', () => {
      expect(isTestFile('Form.test.tsx')).toBe(true);
    });

    it('should match *.spec.jsx files (React JSX)', () => {
      expect(isTestFile('App.spec.jsx')).toBe(true);
    });

    it('should match *.test.jsx files (React JSX)', () => {
      expect(isTestFile('App.test.jsx')).toBe(true);
    });

    it('should NOT match regular source files', () => {
      expect(isTestFile('index.ts')).toBe(false);
      expect(isTestFile('utils.js')).toBe(false);
      expect(isTestFile('App.tsx')).toBe(false);
    });
  });

  describe('Ruby patterns', () => {
    it('should match *_spec.rb files (RSpec)', () => {
      expect(isTestFile('users_controller_spec.rb')).toBe(true);
      expect(isTestFile('user_spec.rb')).toBe(true);
    });

    it('should match *_test.rb files (Minitest)', () => {
      expect(isTestFile('user_test.rb')).toBe(true);
    });

    it('should match test_*.rb files (Minitest prefix)', () => {
      expect(isTestFile('test_user.rb')).toBe(true);
      expect(isTestFile('test_authentication.rb')).toBe(true);
    });

    it('should NOT match regular Ruby files', () => {
      expect(isTestFile('user.rb')).toBe(false);
      expect(isTestFile('application.rb')).toBe(false);
    });
  });

  describe('Python patterns', () => {
    it('should match *_test.py files', () => {
      expect(isTestFile('user_test.py')).toBe(true);
    });

    it('should match test_*.py files (pytest prefix)', () => {
      expect(isTestFile('test_user.py')).toBe(true);
      expect(isTestFile('test_authentication.py')).toBe(true);
    });

    it('should NOT match regular Python files', () => {
      expect(isTestFile('user.py')).toBe(false);
      expect(isTestFile('conftest.py')).toBe(false);
    });
  });

  describe('Java patterns', () => {
    it('should match *Test.java files', () => {
      expect(isTestFile('UserTest.java')).toBe(true);
    });

    it('should match *Tests.java files (plural)', () => {
      expect(isTestFile('UserTests.java')).toBe(true);
    });

    it('should match Test*.java files (prefix)', () => {
      expect(isTestFile('TestUser.java')).toBe(true);
    });

    it('should match *Spec.java files (BDD)', () => {
      expect(isTestFile('UserSpec.java')).toBe(true);
    });

    it('should NOT match regular Java files', () => {
      expect(isTestFile('User.java')).toBe(false);
      expect(isTestFile('Application.java')).toBe(false);
    });
  });

  describe('PHP patterns', () => {
    it('should match *Test.php files (PHPUnit)', () => {
      expect(isTestFile('UserTest.php')).toBe(true);
      expect(isTestFile('AuthTest.php')).toBe(true);
    });

    it('should match *_test.php files (underscore)', () => {
      expect(isTestFile('user_test.php')).toBe(true);
    });

    it('should NOT match regular PHP files', () => {
      expect(isTestFile('User.php')).toBe(false);
      expect(isTestFile('index.php')).toBe(false);
    });
  });

  describe('Elixir patterns', () => {
    it('should match *_test.exs files', () => {
      expect(isTestFile('user_test.exs')).toBe(true);
      expect(isTestFile('user_controller_test.exs')).toBe(true);
    });

    it('should NOT match regular Elixir files', () => {
      expect(isTestFile('user.ex')).toBe(false);
      expect(isTestFile('router.exs')).toBe(false);
    });
  });
});

describe('Excluded Directories', () => {
  it('should exclude node_modules', () => {
    expect(isExcludedDirectory('node_modules')).toBe(true);
  });

  it('should exclude vendor', () => {
    expect(isExcludedDirectory('vendor')).toBe(true);
  });

  it('should exclude .git', () => {
    expect(isExcludedDirectory('.git')).toBe(true);
  });

  it('should exclude build artifacts', () => {
    expect(isExcludedDirectory('dist')).toBe(true);
    expect(isExcludedDirectory('build')).toBe(true);
    expect(isExcludedDirectory('coverage')).toBe(true);
  });

  it('should exclude language-specific dirs', () => {
    expect(isExcludedDirectory('__pycache__')).toBe(true);
    expect(isExcludedDirectory('.pytest_cache')).toBe(true);
    expect(isExcludedDirectory('target')).toBe(true);
    expect(isExcludedDirectory('deps')).toBe(true);
  });

  it('should NOT exclude source directories', () => {
    expect(isExcludedDirectory('src')).toBe(false);
    expect(isExcludedDirectory('lib')).toBe(false);
    expect(isExcludedDirectory('test')).toBe(false);
    expect(isExcludedDirectory('spec')).toBe(false);
  });
});

/**
 * Integration tests that verify the scanning logic works against a real filesystem.
 *
 * These replicate the scanning algorithm from ValidationMode.scanTestFiles()
 * using real fs (via vi.importActual) to avoid mock interference in singleFork mode.
 * The algorithm is: recursively walk directories, skip EXCLUDED_DIRECTORIES,
 * match filenames against TEST_FILE_PATTERNS.
 */
describe('scanTestFiles() Integration', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = realFs.mkdtempSync(realPath.join(realOs.tmpdir(), 'rsolv-scan-'));
  });

  afterEach(() => {
    if (tempDir && realFs.existsSync(tempDir)) {
      realFs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  function createFile(relativePath: string, content: string = '// test file'): void {
    const fullPath = realPath.join(tempDir, relativePath);
    realFs.mkdirSync(realPath.dirname(fullPath), { recursive: true });
    realFs.writeFileSync(fullPath, content);
  }

  /**
   * Replicate ValidationMode.scanTestFiles() scanning logic using real fs.
   * This ensures we test the same patterns/exclusions without mock interference.
   */
  function scanTestFilesReal(rootDir: string): string[] {
    const testFiles: string[] = [];
    const scanDirectory = (dir: string): void => {
      try {
        const entries = realFs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
          const fullPath = realPath.join(dir, entry.name);
          if (entry.isDirectory()) {
            if (!EXCLUDED_DIRECTORIES.has(entry.name)) {
              scanDirectory(fullPath);
            }
          } else if (entry.isFile()) {
            if (TEST_FILE_PATTERNS.some((pattern: RegExp) => pattern.test(entry.name))) {
              testFiles.push(fullPath);
            }
          }
        }
      } catch {
        // Directory might not exist or be unreadable, skip it
      }
    };
    scanDirectory(rootDir);
    return [...new Set(testFiles)];
  }

  it('should find test files in a multi-language repo', () => {
    createFile('src/app.test.ts');
    createFile('spec/models/user_spec.rb');
    createFile('tests/test_utils.py');
    createFile('tests/Unit/UserTest.php');
    createFile('test/rsolv/user_test.exs');

    const files = scanTestFilesReal(tempDir);

    expect(files.length).toBe(5);
    expect(files.some((f: string) => f.endsWith('app.test.ts'))).toBe(true);
    expect(files.some((f: string) => f.endsWith('user_spec.rb'))).toBe(true);
    expect(files.some((f: string) => f.endsWith('test_utils.py'))).toBe(true);
    expect(files.some((f: string) => f.endsWith('UserTest.php'))).toBe(true);
    expect(files.some((f: string) => f.endsWith('user_test.exs'))).toBe(true);
  });

  it('should return empty array when no test files exist', () => {
    createFile('src/index.ts', 'export default {}');

    const files = scanTestFilesReal(tempDir);

    expect(files).toEqual([]);
  });

  it('should exclude node_modules', () => {
    createFile('node_modules/pkg/test.spec.js');
    createFile('src/app.test.ts');

    const files = scanTestFilesReal(tempDir);

    expect(files.every((f: string) => !f.includes('node_modules'))).toBe(true);
    expect(files.some((f: string) => f.endsWith('app.test.ts'))).toBe(true);
  });

  it('should exclude vendor directory', () => {
    createFile('vendor/bundle/test_spec.rb');
    createFile('spec/user_spec.rb');

    const files = scanTestFilesReal(tempDir);

    expect(files.every((f: string) => !f.includes('vendor'))).toBe(true);
    expect(files.some((f: string) => f.endsWith('user_spec.rb'))).toBe(true);
  });

  it('should handle empty directories', () => {
    const files = scanTestFilesReal(tempDir);
    expect(files).toEqual([]);
  });
});
