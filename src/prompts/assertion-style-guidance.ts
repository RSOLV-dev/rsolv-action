/**
 * Assertion Style Guidance
 * RFC-103: RED Test Generation Quality Improvements
 *
 * Provides guidance on which assertion library/style to use based on
 * what's actually available in the project. This prevents the LLM from
 * generating tests that use unavailable libraries like chai or sinon.
 */

export type AssertionStyle = 'bdd' | 'tdd' | 'jest';

export interface AssertionStyleGuidance {
  style: AssertionStyle;
  preferredLibrary: string;
  syntaxExample: string;
  importStatement: string;
  doNotUse: string[];
  versionWarning?: string;
  safeAssertions?: string[];
  unsafeAssertions?: string[];
}

/**
 * Maps assertion libraries to their style category.
 */
export const ASSERTION_LIBRARY_STYLES: Record<string, AssertionStyle> = {
  // BDD-style (should/expect chain syntax)
  should: 'bdd',
  chai: 'bdd',
  'expect.js': 'bdd',
  expect: 'bdd',

  // Jest/Vitest style (expect().toBe())
  jest: 'jest',
  vitest: 'jest',
  '@jest/globals': 'jest',

  // TDD-style (assert.xyz())
  assert: 'tdd',
  'assert (Node built-in)': 'tdd',
  'power-assert': 'tdd',
};

/**
 * Priority order for selecting preferred library.
 * Higher index = higher priority.
 */
const LIBRARY_PRIORITY: string[] = [
  'assert',
  'assert (Node built-in)',
  'power-assert',
  'should',
  'expect.js',
  'expect',
  'chai',
  'vitest',
  'jest',
];

/**
 * Common test libraries that might be unavailable.
 * Includes 'assert' to warn against Node built-in when better alternatives exist.
 */
const COMMON_TEST_LIBRARIES = [
  'chai',
  'should',
  'expect',
  'expect.js',
  'sinon',
  'testdouble',
  'jest',
  'vitest',
  'nock',
  'msw',
  'supertest',
  'assert', // Node built-in - warn when BDD/Jest alternatives available
];

/**
 * Node.js assert methods that are safe across all Node versions.
 */
const SAFE_ASSERT_METHODS = [
  'assert.ok',
  'assert.strictEqual',
  'assert.notStrictEqual',
  'assert.deepStrictEqual',
  'assert.notDeepStrictEqual',
  'assert.throws',
  'assert.doesNotThrow',
  'assert.fail',
  'assert.ifError',
];

/**
 * Node.js assert methods that require Node 16+ and may not be available.
 */
const UNSAFE_ASSERT_METHODS = [
  'assert.match',
  'assert.doesNotMatch',
  'assert.rejects',
  'assert.doesNotReject',
];

/**
 * Get assertion style guidance based on detected libraries.
 *
 * @param ecosystem - The programming language/ecosystem
 * @param detectedLibraries - List of available test libraries
 * @returns Guidance on which assertion style to use
 */
export function getAssertionStyleGuidance(
  ecosystem: string,
  detectedLibraries: string[]
): AssertionStyleGuidance {
  // Normalize library names
  const normalizedLibs = detectedLibraries.map((lib) => lib.toLowerCase().trim());

  // Find the highest-priority available library
  let preferredLibrary = 'assert';
  let highestPriority = -1;

  for (const lib of normalizedLibs) {
    // Handle "assert (Node built-in)" format
    const normalizedLib = lib.includes('assert') ? 'assert' : lib;
    const priority = LIBRARY_PRIORITY.indexOf(normalizedLib);

    if (priority > highestPriority) {
      highestPriority = priority;
      preferredLibrary = normalizedLib;
    }
  }

  // Determine which libraries to warn against using
  const availableSet = new Set(normalizedLibs.map((l) => (l.includes('assert') ? 'assert' : l)));
  const doNotUse = COMMON_TEST_LIBRARIES.filter((lib) => !availableSet.has(lib.toLowerCase()));

  const style = ASSERTION_LIBRARY_STYLES[preferredLibrary] || 'tdd';
  const isTypeScript = ecosystem === 'typescript';

  return buildGuidance(style, preferredLibrary, doNotUse, isTypeScript);
}

function buildGuidance(
  style: AssertionStyle,
  preferredLibrary: string,
  doNotUse: string[],
  isTypeScript: boolean
): AssertionStyleGuidance {
  switch (style) {
  case 'jest':
    return buildJestGuidance(preferredLibrary, doNotUse, isTypeScript);
  case 'bdd':
    return buildBddGuidance(preferredLibrary, doNotUse, isTypeScript);
  case 'tdd':
  default:
    return buildTddGuidance(preferredLibrary, doNotUse, isTypeScript);
  }
}

function buildJestGuidance(
  library: string,
  doNotUse: string[],
  isTypeScript: boolean
): AssertionStyleGuidance {
  const isVitest = library === 'vitest';

  let importStatement: string;
  if (isVitest) {
    // Vitest is ESM-first - always use ES import syntax
    importStatement = 'import { describe, it, expect } from \'vitest\';';
  } else {
    // Jest - globals are auto-available, but TypeScript needs imports for types
    importStatement = isTypeScript
      ? 'import { describe, it, expect } from \'@jest/globals\';'
      : ''; // Jest globals are auto-available in JS
  }

  return {
    style: 'jest',
    preferredLibrary: library,
    syntaxExample: 'expect(value).toBe(expected);\nexpect(string).toMatch(/pattern/);\nexpect(array).toContain(item);',
    importStatement,
    doNotUse: doNotUse.filter((l) => l !== library),
  };
}

function buildBddGuidance(
  library: string,
  doNotUse: string[],
  isTypeScript: boolean
): AssertionStyleGuidance {
  if (library === 'chai') {
    return {
      style: 'bdd',
      preferredLibrary: 'chai',
      syntaxExample: 'expect(value).to.equal(expected);\nexpect(string).to.match(/pattern/);\nexpect(array).to.include(item);',
      importStatement: isTypeScript
        ? 'import { expect } from \'chai\';'
        : 'const { expect } = require(\'chai\');',
      doNotUse: doNotUse.filter((l) => l !== 'chai'),
    };
  }

  if (library === 'should') {
    return {
      style: 'bdd',
      preferredLibrary: 'should',
      syntaxExample: 'value.should.equal(expected);\nstring.should.match(/pattern/);\narray.should.containEql(item);',
      importStatement: isTypeScript ? 'import \'should\';' : 'require(\'should\');',
      doNotUse: doNotUse.filter((l) => l !== 'should'),
    };
  }

  // expect.js or generic expect
  return {
    style: 'bdd',
    preferredLibrary: library,
    syntaxExample: 'expect(value).to.be(expected);\nexpect(string).to.match(/pattern/);',
    importStatement: isTypeScript
      ? `import expect from '${library}';`
      : `const expect = require('${library}');`,
    doNotUse: doNotUse.filter((l) => l !== library),
  };
}

function buildTddGuidance(
  library: string,
  doNotUse: string[],
  isTypeScript: boolean
): AssertionStyleGuidance {
  return {
    style: 'tdd',
    preferredLibrary: 'assert',
    syntaxExample: 'assert.strictEqual(actual, expected);\nassert.ok(condition);\nassert.deepStrictEqual(obj1, obj2);',
    importStatement: isTypeScript
      ? 'import assert from \'assert\';'
      : 'const assert = require(\'assert\');',
    doNotUse: doNotUse.filter((l) => l !== 'assert'),
    versionWarning:
      'Node.js assert module has version-dependent APIs. Use only these safe methods: ' +
      SAFE_ASSERT_METHODS.join(', ') +
      '. AVOID these (require Node 16+): ' +
      UNSAFE_ASSERT_METHODS.join(', '),
    safeAssertions: [...SAFE_ASSERT_METHODS],
    unsafeAssertions: [...UNSAFE_ASSERT_METHODS],
  };
}
