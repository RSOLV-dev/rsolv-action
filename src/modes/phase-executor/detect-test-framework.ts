import { existsSync, readFileSync } from 'fs';
import { join } from 'path';

/**
 * Detect the test framework from the current repo's file structure.
 * Returns a best-guess framework name for the backend orchestrator.
 */
export function detectTestFramework(cwd: string): string {
  // Check for framework-specific files/dirs
  if (existsSync(join(cwd, 'spec'))) return 'rspec';
  if (existsSync(join(cwd, 'test', 'test_helper.exs'))) return 'exunit';
  if (existsSync(join(cwd, 'vitest.config.ts')) || existsSync(join(cwd, 'vitest.config.js'))) return 'vitest';
  if (existsSync(join(cwd, 'jest.config.ts')) || existsSync(join(cwd, 'jest.config.js'))) return 'jest';
  if (existsSync(join(cwd, 'pytest.ini')) || existsSync(join(cwd, 'conftest.py'))) return 'pytest';
  if (existsSync(join(cwd, 'phpunit.xml')) || existsSync(join(cwd, 'phpunit.xml.dist'))) return 'phpunit';
  if (existsSync(join(cwd, 'pom.xml'))) return 'junit';
  if (existsSync(join(cwd, 'build.gradle')) || existsSync(join(cwd, 'build.gradle.kts'))) return 'junit';

  // Check package.json for test runner
  try {
    const pkgPath = join(cwd, 'package.json');
    if (existsSync(pkgPath)) {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      if (deps.vitest) return 'vitest';
      if (deps.jest) return 'jest';
      if (deps.mocha) return 'mocha';
    }
  } catch {
    // ignore parse errors
  }

  // Check Gemfile for test runner
  try {
    const gemfilePath = join(cwd, 'Gemfile');
    if (existsSync(gemfilePath)) {
      const gemfile = readFileSync(gemfilePath, 'utf-8');
      if (gemfile.includes('rspec')) return 'rspec';
      if (gemfile.includes('minitest')) return 'minitest';
    }
  } catch {
    // ignore read errors
  }

  // Check requirements.txt / pyproject.toml for pytest
  try {
    const reqPath = join(cwd, 'requirements.txt');
    if (existsSync(reqPath)) {
      const reqs = readFileSync(reqPath, 'utf-8');
      if (reqs.includes('pytest')) return 'pytest';
    }
  } catch {
    // ignore
  }

  return 'unknown';
}
