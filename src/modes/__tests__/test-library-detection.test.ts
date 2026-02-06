/**
 * Tests for Multi-Ecosystem Test Library Detection
 * RFC-103: RED Test Generation Quality Improvements
 */

import { describe, it, expect } from 'vitest';
import { extractTestLibraries, STDLIB_LIBRARIES, hasNoTestFramework } from '../test-library-detection.js';

describe('extractTestLibraries', () => {
  describe('Python', () => {
    it('always includes unittest (stdlib)', () => {
      const libs = extractTestLibraries('python', {});
      expect(libs).toContain('unittest');
    });

    it('detects pytest from requirements.txt', () => {
      const manifests = { 'requirements.txt': 'pytest==7.4.0\nrequests>=2.28\nflask==2.0' };
      const libs = extractTestLibraries('python', manifests);
      expect(libs).toContain('pytest');
    });

    it('detects pytest-mock from pyproject.toml', () => {
      const manifests = {
        'pyproject.toml': `[tool.poetry.dev-dependencies]
pytest-mock = "^3.10"
mock = "^5.0"`
      };
      const libs = extractTestLibraries('python', manifests);
      expect(libs).toContain('pytest-mock');
      expect(libs).toContain('mock');
    });

    it('returns only stdlib when no manifests', () => {
      const libs = extractTestLibraries('python', null);
      expect(libs).toEqual(['unittest']);
    });
  });

  describe('Ruby', () => {
    it('always includes minitest (stdlib)', () => {
      const libs = extractTestLibraries('ruby', {});
      expect(libs).toContain('minitest');
    });

    it('detects rspec from Gemfile', () => {
      const manifests = { 'Gemfile': "gem 'rspec', '~> 3.12'\ngem 'rails'" };
      const libs = extractTestLibraries('ruby', manifests);
      expect(libs).toContain('rspec');
    });
  });

  describe('Elixir', () => {
    it('always includes ExUnit (stdlib)', () => {
      const libs = extractTestLibraries('elixir', {});
      expect(libs).toContain('ExUnit');
    });

    it('detects mox from mix.exs', () => {
      const manifests = {
        'mix.exs': `defp deps do
  [{:mox, "~> 1.0", only: :test}, {:bypass, "~> 2.1", only: :test}]
end`
      };
      const libs = extractTestLibraries('elixir', manifests);
      expect(libs).toContain('mox');
      expect(libs).toContain('bypass');
    });
  });

  describe('PHP', () => {
    it('detects phpunit from composer.json', () => {
      const manifests = {
        'composer.json': JSON.stringify({
          'require-dev': { 'phpunit/phpunit': '^10.0', 'mockery/mockery': '^1.6' }
        })
      };
      const libs = extractTestLibraries('php', manifests);
      expect(libs).toContain('phpunit');
      expect(libs).toContain('mockery');
    });
  });

  describe('Java', () => {
    it('detects junit from pom.xml', () => {
      const manifests = {
        'pom.xml': `<dependency>
  <groupId>org.junit.jupiter</groupId>
  <artifactId>junit-jupiter</artifactId>
  <scope>test</scope>
</dependency>`
      };
      const libs = extractTestLibraries('java', manifests);
      expect(libs).toContain('junit-jupiter');
    });
  });

  describe('JavaScript', () => {
    it('detects mocha and sinon from package.json', () => {
      const manifests = {
        'package.json': JSON.stringify({
          devDependencies: { mocha: '^10.0', sinon: '^15.0', chai: '^4.3' }
        })
      };
      const libs = extractTestLibraries('javascript', manifests);
      expect(libs).toContain('mocha');
      expect(libs).toContain('sinon');
      expect(libs).toContain('chai');
    });

    it('adds Node built-in assert when other libraries found', () => {
      const manifests = {
        'package.json': JSON.stringify({
          devDependencies: { mocha: '^10.0' }
        })
      };
      const libs = extractTestLibraries('javascript', manifests);
      expect(libs).toContain('assert (Node built-in)');
    });
  });

  describe('STDLIB_LIBRARIES', () => {
    it('defines stdlib for each ecosystem', () => {
      expect(STDLIB_LIBRARIES.python).toContain('unittest');
      expect(STDLIB_LIBRARIES.ruby).toContain('minitest');
      expect(STDLIB_LIBRARIES.elixir).toContain('ExUnit');
      expect(STDLIB_LIBRARIES.javascript).toContain('assert');
    });
  });
});

describe('hasNoTestFramework', () => {
  describe('JavaScript', () => {
    it('returns true when only assert (stdlib) is present', () => {
      expect(hasNoTestFramework('javascript', ['assert'])).toBe(true);
    });

    it('returns true when only assert (Node built-in) is present', () => {
      expect(hasNoTestFramework('javascript', ['assert', 'assert (Node built-in)'])).toBe(true);
    });

    it('returns false when mocha is present', () => {
      expect(hasNoTestFramework('javascript', ['assert', 'mocha'])).toBe(false);
    });

    it('returns false when vitest is present', () => {
      expect(hasNoTestFramework('javascript', ['vitest'])).toBe(false);
    });
  });

  describe('Python', () => {
    it('returns true when only unittest (stdlib) is present', () => {
      expect(hasNoTestFramework('python', ['unittest'])).toBe(true);
    });

    it('returns false when pytest is present', () => {
      expect(hasNoTestFramework('python', ['unittest', 'pytest'])).toBe(false);
    });
  });

  describe('Ruby', () => {
    it('returns true when only minitest/test-unit (stdlib) is present', () => {
      expect(hasNoTestFramework('ruby', ['minitest', 'test/unit'])).toBe(true);
    });

    it('returns false when rspec is present', () => {
      expect(hasNoTestFramework('ruby', ['minitest', 'rspec'])).toBe(false);
    });

    it('returns false when capybara (minitest helper) is present', () => {
      expect(hasNoTestFramework('ruby', ['minitest', 'capybara'])).toBe(false);
    });
  });

  describe('PHP', () => {
    it('returns true when no libraries present (PHP has no stdlib test framework)', () => {
      expect(hasNoTestFramework('php', [])).toBe(true);
    });

    it('returns false when phpunit is present', () => {
      expect(hasNoTestFramework('php', ['phpunit'])).toBe(false);
    });
  });

  describe('Java', () => {
    it('returns true when no libraries present (Java has no stdlib test framework)', () => {
      expect(hasNoTestFramework('java', [])).toBe(true);
    });

    it('returns false when junit is present', () => {
      expect(hasNoTestFramework('java', ['junit-jupiter'])).toBe(false);
    });
  });

  describe('Elixir', () => {
    it('returns true when only ExUnit (stdlib) is present', () => {
      expect(hasNoTestFramework('elixir', ['ExUnit'])).toBe(true);
    });

    it('returns false when mox is present', () => {
      expect(hasNoTestFramework('elixir', ['ExUnit', 'mox'])).toBe(false);
    });
  });

  describe('Edge cases', () => {
    it('returns true when empty array', () => {
      expect(hasNoTestFramework('javascript', [])).toBe(true);
    });

    it('handles case insensitivity', () => {
      expect(hasNoTestFramework('ruby', ['MINITEST'])).toBe(true);
      expect(hasNoTestFramework('ruby', ['RSpec'])).toBe(false);
    });
  });
});
