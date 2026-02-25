/**
 * Test Library Detection Across All Ecosystems
 * RFC-103: RED Test Generation Quality Improvements
 *
 * Extends library detection from JavaScript-only to all 6 ecosystems:
 * Python, Ruby, Elixir, PHP, Java, JavaScript
 */

export type Ecosystem = 'python' | 'ruby' | 'elixir' | 'php' | 'java' | 'javascript' | 'typescript';

/**
 * Standard library test frameworks that are always available in each ecosystem.
 */
export const STDLIB_LIBRARIES: Record<string, string[]> = {
  python: ['unittest'],
  ruby: ['minitest', 'test/unit'],
  elixir: ['ExUnit'],
  php: [], // PHP has no built-in test framework
  java: [], // Java has no built-in test framework
  javascript: ['assert'],
  typescript: ['assert'],
};

/**
 * Known test-related libraries for each ecosystem.
 * Only libraries in this list will be detected and reported.
 */
const TEST_LIBRARY_PATTERNS: Record<string, string[]> = {
  python: [
    'pytest', 'pytest-mock', 'mock', 'unittest-mock',
    'hypothesis', 'faker', 'factory-boy',
    'responses', 'httpretty', 'vcrpy', 'requests-mock',
    'nose', 'nose2', 'tox', 'coverage'
  ],
  ruby: [
    'rspec', 'rspec-rails', 'rspec-mocks',
    'webmock', 'vcr', 'factory_bot', 'factory_bot_rails',
    'shoulda-matchers', 'capybara', 'faker',
    'simplecov', 'database_cleaner'
  ],
  elixir: [
    'mox', 'bypass', 'ex_machina', 'faker',
    'mock', 'mimic', 'wallaby', 'hound',
    'stream_data', 'excoveralls'
  ],
  php: [
    'phpunit', 'pest', 'mockery', 'prophecy',
    'faker', 'codeception', 'phpspec',
    'infection', 'behat'
  ],
  java: [
    'junit', 'junit-jupiter', 'junit4', 'junit5',
    'mockito', 'assertj', 'hamcrest',
    'testng', 'easymock', 'powermock',
    'wiremock', 'rest-assured'
  ],
  javascript: [
    'chai', 'should', 'expect', 'expect.js', 'power-assert',
    'mocha', 'jest', 'vitest', 'ava', 'tape', 'jasmine',
    'sinon', 'testdouble', 'nock', 'msw',
    'supertest', 'superagent',
    '@testing-library/react', '@testing-library/jest-dom', 'enzyme',
    'faker', '@faker-js/faker', 'chance'
  ],
  typescript: [
    'chai', 'should', 'expect', 'expect.js', 'power-assert',
    'mocha', 'jest', 'vitest', 'ava', 'tape', 'jasmine',
    'sinon', 'testdouble', 'nock', 'msw',
    'supertest', 'superagent',
    '@testing-library/react', '@testing-library/jest-dom', 'enzyme',
    'faker', '@faker-js/faker', 'chance'
  ],
};

/**
 * Composite/starter dependencies that bundle multiple test libraries.
 * When we detect one of these artifact names, we expand to the implied libraries.
 * Handles Java starters (Spring Boot, Quarkus, Micronaut, Dropwizard).
 */
const COMPOSITE_TEST_DEPENDENCIES: Record<string, Record<string, string[]>> = {
  java: {
    'spring-boot-starter-test': ['junit-jupiter', 'mockito', 'assertj', 'hamcrest'],
    'quarkus-junit5': ['junit-jupiter'],
    'quarkus-junit5-mockito': ['junit-jupiter', 'mockito'],
    'micronaut-test-junit5': ['junit-jupiter'],
    'dropwizard-testing': ['junit-jupiter', 'assertj'],
    'vertx-junit5': ['junit-jupiter'],
    'camel-test-junit5': ['junit-jupiter'],
    'helidon-testing-junit5': ['junit-jupiter'],
    'arquillian-junit5-container': ['junit-jupiter'],
  },
};

/**
 * Extract test libraries from project manifests for all ecosystems.
 *
 * @param ecosystem - The programming language/ecosystem
 * @param manifests - Map of manifest file names to their contents
 * @returns Array of available test library names
 */
export function extractTestLibraries(
  ecosystem: Ecosystem | string,
  manifests: Record<string, string> | null
): string[] {
  const stdlib = STDLIB_LIBRARIES[ecosystem] || [];
  const patterns = TEST_LIBRARY_PATTERNS[ecosystem];

  if (!patterns) {
    return stdlib.length > 0 ? [...stdlib] : [];
  }

  if (!manifests) {
    return [...stdlib];
  }

  const found = new Set<string>(stdlib);

  switch (ecosystem) {
  case 'python':
    extractPythonLibraries(manifests, patterns, found);
    break;
  case 'ruby':
    extractRubyLibraries(manifests, patterns, found);
    break;
  case 'elixir':
    extractElixirLibraries(manifests, patterns, found);
    break;
  case 'php':
    extractPhpLibraries(manifests, patterns, found);
    break;
  case 'java':
    extractJavaLibraries(manifests, patterns, found);
    break;
  case 'javascript':
  case 'typescript':
    extractJavaScriptLibraries(manifests, patterns, found);
    // Always add Node's built-in assert
    if (found.size > stdlib.length && !found.has('assert (Node built-in)')) {
      found.add('assert (Node built-in)');
    }
    break;
  }

  return Array.from(found);
}

function extractPythonLibraries(
  manifests: Record<string, string>,
  patterns: string[],
  found: Set<string>
): void {
  // Check requirements.txt
  const requirements = manifests['requirements.txt'] || manifests['requirements-dev.txt'] || '';
  for (const pattern of patterns) {
    // Match: pytest==7.4.0, pytest>=7.0, pytest
    const regex = new RegExp(`^${escapeRegex(pattern)}[=<>~!\\s]`, 'im');
    if (regex.test(requirements)) {
      found.add(pattern);
    }
  }

  // Check pyproject.toml
  const pyproject = manifests['pyproject.toml'] || '';
  for (const pattern of patterns) {
    // Match in various sections: dev-dependencies, optional-dependencies, etc.
    const escaped = escapeRegex(pattern);
    const regexes = [
      new RegExp(`["']${escaped}["']`, 'i'), // "pytest" or 'pytest'
      new RegExp(`${escaped}\\s*[=<>~]`, 'i'), // pytest>=7.0
      new RegExp(`${escaped}\\s*,`, 'i'), // pytest, hypothesis
    ];
    for (const regex of regexes) {
      if (regex.test(pyproject)) {
        found.add(pattern);
        break;
      }
    }
  }
}

function extractRubyLibraries(
  manifests: Record<string, string>,
  patterns: string[],
  found: Set<string>
): void {
  const gemfile = manifests['Gemfile'] || manifests['gemfile'] || '';

  for (const pattern of patterns) {
    // Match: gem 'rspec', gem "rspec-rails"
    const escaped = escapeRegex(pattern);
    const regex = new RegExp(`gem\\s+['"]${escaped}['"]`, 'i');
    if (regex.test(gemfile)) {
      found.add(pattern);
    }
  }
}

function extractElixirLibraries(
  manifests: Record<string, string>,
  patterns: string[],
  found: Set<string>
): void {
  const mixfile = manifests['mix.exs'] || '';

  for (const pattern of patterns) {
    // Match: {:mox, "~> 1.0"} or {:bypass, ...}
    const escaped = escapeRegex(pattern);
    const regex = new RegExp(`\\{:${escaped},`, 'i');
    if (regex.test(mixfile)) {
      found.add(pattern);
    }
  }
}

function extractPhpLibraries(
  manifests: Record<string, string>,
  patterns: string[],
  found: Set<string>
): void {
  const composerJson = manifests['composer.json'];
  if (!composerJson) return;

  try {
    const composer = JSON.parse(composerJson) as {
      'require-dev'?: Record<string, string>;
      require?: Record<string, string>;
    };

    const allDeps = {
      ...composer.require,
      ...composer['require-dev'],
    };

    for (const pattern of patterns) {
      // PHP packages use vendor/package format, check the package name
      for (const dep of Object.keys(allDeps)) {
        const packageName = dep.split('/').pop() || '';
        if (packageName.toLowerCase().includes(pattern.toLowerCase())) {
          found.add(pattern);
        }
      }
    }
  } catch {
    // Invalid JSON, skip
  }
}

function extractJavaLibraries(
  manifests: Record<string, string>,
  patterns: string[],
  found: Set<string>
): void {
  // Check pom.xml (Maven)
  const pomXml = manifests['pom.xml'] || '';
  for (const pattern of patterns) {
    const escaped = escapeRegex(pattern);
    // Match: <artifactId>junit-jupiter</artifactId> or <artifactId>mockito-core</artifactId>
    const regex = new RegExp(`<artifactId>[^<]*${escaped}[^<]*</artifactId>`, 'i');
    if (regex.test(pomXml)) {
      found.add(pattern);
    }
  }

  // Check build.gradle and build.gradle.kts (Gradle)
  const gradle = manifests['build.gradle'] || manifests['build.gradle.kts'] || '';
  for (const pattern of patterns) {
    const escaped = escapeRegex(pattern);
    // Match: testImplementation 'org.mockito:mockito-core:5.3.1' or testImplementation("org.junit.jupiter:junit-jupiter:5.9.2")
    // Look for pattern anywhere in the dependency string (after a colon, to match artifact name)
    const regex = new RegExp(`:${escaped}[^'"]*['"]`, 'i');
    if (regex.test(gradle)) {
      found.add(pattern);
    }
  }

  // Composite dependency expansion (e.g., spring-boot-starter-test → junit-jupiter + mockito)
  const composites = COMPOSITE_TEST_DEPENDENCIES['java'] || {};
  for (const [starter, implied] of Object.entries(composites)) {
    const escaped = escapeRegex(starter);
    const pomRegex = new RegExp(`<artifactId>[^<]*${escaped}[^<]*</artifactId>`, 'i');
    const gradleRegex = new RegExp(`${escaped}`, 'i');

    if (pomRegex.test(pomXml) || gradleRegex.test(gradle)) {
      for (const lib of implied) {
        found.add(lib);
      }
    }
  }
}

function extractJavaScriptLibraries(
  manifests: Record<string, string>,
  patterns: string[],
  found: Set<string>
): void {
  const packageJsonStr = manifests['package.json'];
  if (!packageJsonStr) return;

  try {
    const packageJson = JSON.parse(packageJsonStr) as {
      devDependencies?: Record<string, string>;
      dependencies?: Record<string, string>;
    };

    const allDeps = {
      ...packageJson.dependencies,
      ...packageJson.devDependencies,
    };

    for (const pattern of patterns) {
      if (allDeps[pattern]) {
        found.add(pattern);
      }
    }
  } catch {
    // Invalid JSON, skip
  }
}

/**
 * Escape special regex characters in a string.
 */
function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Stdlib libraries that ARE real test frameworks (can run tests natively).
 * These should NOT trigger "no test framework available" errors.
 *
 * - Python's unittest: `python -m unittest discover` runs tests
 * - Ruby's minitest/test-unit: `ruby -Ilib:test test/*.rb` runs tests
 * - Elixir's ExUnit: `mix test` runs tests
 *
 * Contrast with Node's `assert`: it's just assertions, no test runner.
 */
const STDLIB_TEST_FRAMEWORKS = ['unittest', 'minitest', 'test/unit', 'exunit'];

/**
 * Check if a project has no real test framework installed.
 * Returns true if only assertion libraries are present (no test runner capability).
 *
 * Use case: DVNA has `assert` from Node stdlib but no mocha/jest/vitest.
 * The LLM might generate vitest tests, but vitest isn't available.
 *
 * IMPORTANT: stdlib test frameworks (unittest, ExUnit, minitest) ARE real frameworks
 * and should NOT trigger this check. Only pure assertion libraries (Node's assert) should.
 *
 * @param ecosystem - The programming language/ecosystem
 * @param availableLibraries - Libraries detected from manifests
 * @returns true if only assertion libraries are present (no test framework/runner)
 */
export function hasNoTestFramework(
  ecosystem: Ecosystem | string,
  availableLibraries: string[]
): boolean {
  const stdlib = STDLIB_LIBRARIES[ecosystem] || [];

  // If no libraries at all, definitely no framework
  if (availableLibraries.length === 0) {
    return true;
  }

  // Check if any available library is a real test framework (stdlib or external)
  const normalizedAvailable = availableLibraries.map(l => l.toLowerCase());

  // If any stdlib test framework is present, we CAN run tests
  for (const stdlibFramework of STDLIB_TEST_FRAMEWORKS) {
    if (normalizedAvailable.includes(stdlibFramework)) {
      return false; // This stdlib IS a real test framework
    }
  }

  // Check for external test frameworks (anything not in stdlib assertions)
  const normalizedStdlib = stdlib.map(l => l.toLowerCase());

  // Filter out stdlib assertions and "Node built-in" variants
  const nonStdlib = normalizedAvailable.filter(lib => {
    if (normalizedStdlib.includes(lib)) return false;
    if (lib.includes('(node built-in)') || lib === 'assert (node built-in)') return false;
    return true;
  });

  // If nothing remains after filtering stdlib assertions, there's no real test framework
  return nonStdlib.length === 0;
}
