/**
 * Shared test file patterns and excluded directories
 *
 * Single source of truth for identifying test files across all supported
 * languages. Used by scanTestFiles() in ValidationMode and available
 * to other components that need test file detection.
 *
 * Supported languages (from src/security/pattern-source.ts):
 *   javascript, typescript, python, ruby, java, php, elixir
 */

/**
 * Regex patterns for matching test file names (applied to basename only).
 * Organized by language/framework.
 */
export const TEST_FILE_PATTERNS: RegExp[] = [
  // JavaScript/TypeScript (Jest, Vitest, Mocha, Jasmine)
  /\.spec\.ts$/,
  /\.spec\.js$/,
  /\.test\.ts$/,
  /\.test\.js$/,
  /\.spec\.tsx$/,
  /\.spec\.jsx$/,
  /\.test\.tsx$/,
  /\.test\.jsx$/,
  /_spec\.ts$/,    // Jasmine underscore convention
  /_spec\.js$/,    // Jasmine underscore convention

  // Ruby (RSpec + Minitest)
  /_spec\.rb$/,    // RSpec convention
  /_test\.rb$/,    // Minitest suffix convention
  /^test_.*\.rb$/, // Minitest prefix convention

  // Python (pytest, unittest)
  /_test\.py$/,    // pytest suffix convention
  /^test_.*\.py$/, // pytest prefix convention

  // Java (JUnit, TestNG, Spock)
  /Test\.java$/,   // JUnit standard (ends with Test.java)
  /Tests\.java$/,  // JUnit plural convention
  /^Test.*\.java$/, // JUnit prefix convention
  /Spec\.java$/,   // Spock BDD convention

  // PHP (PHPUnit, Pest)
  /Test\.php$/,    // PHPUnit standard
  /_test\.php$/,   // PHPUnit underscore convention

  // Elixir (ExUnit)
  /_test\.exs$/
];

/**
 * Directory names to exclude when scanning for test files.
 * These contain dependencies, build artifacts, or VCS metadata.
 */
export const EXCLUDED_DIRECTORIES: Set<string> = new Set([
  'node_modules',
  'vendor',
  '.git',
  'dist',
  'build',
  'coverage',
  '__pycache__',
  '.pytest_cache',
  'target',  // Java/Rust build dir
  'deps'     // Elixir deps dir
]);

/**
 * Check if a filename matches any test file pattern.
 */
export function isTestFile(filename: string): boolean {
  return TEST_FILE_PATTERNS.some(pattern => pattern.test(filename));
}

/**
 * Check if a directory name should be excluded from scanning.
 */
export function isExcludedDirectory(dirname: string): boolean {
  return EXCLUDED_DIRECTORIES.has(dirname);
}
