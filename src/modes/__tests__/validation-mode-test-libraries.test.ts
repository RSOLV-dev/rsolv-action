/**
 * Tests for Test Library Detection Across All Ecosystems
 * RFC-103: RED Test Generation Quality Improvements
 */

import { describe, it, expect } from 'vitest';
import { extractTestLibraries, STDLIB_LIBRARIES } from '../test-library-detection.js';

describe('extractTestLibraries', () => {
  describe('Python', () => {
    it('always includes unittest (stdlib)', () => {
      const libs = extractTestLibraries('python', {});
      expect(libs).toContain('unittest');
    });

    it('detects pytest from requirements.txt', () => {
      const manifests = { 'requirements.txt': 'pytest==7.4.0\nrequests>=2.28' };
      const libs = extractTestLibraries('python', manifests);
      expect(libs).toContain('pytest');
      expect(libs).not.toContain('requests'); // Not a test library
    });

    it('detects pytest-mock from pyproject.toml dev dependencies', () => {
      const manifests = {
        'pyproject.toml': `[tool.poetry.dev-dependencies]
pytest-mock = "^3.10"
mock = "^5.0"`
      };
      const libs = extractTestLibraries('python', manifests);
      expect(libs).toContain('pytest-mock');
      expect(libs).toContain('mock');
    });

    it('detects test deps from pyproject.toml optional-dependencies.test', () => {
      const manifests = {
        'pyproject.toml': `[project.optional-dependencies]
test = ["pytest>=7.0", "hypothesis>=6.0", "faker"]`
      };
      const libs = extractTestLibraries('python', manifests);
      expect(libs).toContain('pytest');
      expect(libs).toContain('hypothesis');
      expect(libs).toContain('faker');
    });

    it('detects responses and httpretty', () => {
      const manifests = { 'requirements.txt': 'responses==0.23.1\nhttpretty>=1.1' };
      const libs = extractTestLibraries('python', manifests);
      expect(libs).toContain('responses');
      expect(libs).toContain('httpretty');
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
      expect(libs).not.toContain('rails');
    });

    it('detects test gems in :test group', () => {
      const manifests = {
        'Gemfile': `group :test do
  gem 'webmock'
  gem 'vcr'
  gem 'factory_bot'
end`
      };
      const libs = extractTestLibraries('ruby', manifests);
      expect(libs).toContain('webmock');
      expect(libs).toContain('vcr');
      expect(libs).toContain('factory_bot');
    });

    it('detects shoulda-matchers and capybara', () => {
      const manifests = {
        'Gemfile': "gem 'shoulda-matchers'\ngem 'capybara'"
      };
      const libs = extractTestLibraries('ruby', manifests);
      expect(libs).toContain('shoulda-matchers');
      expect(libs).toContain('capybara');
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

    it('detects ex_machina and faker', () => {
      const manifests = {
        'mix.exs': `{:ex_machina, "~> 2.7", only: :test},
{:faker, "~> 0.17", only: [:dev, :test]}`
      };
      const libs = extractTestLibraries('elixir', manifests);
      expect(libs).toContain('ex_machina');
      expect(libs).toContain('faker');
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

    it('detects pest and prophecy', () => {
      const manifests = {
        'composer.json': JSON.stringify({
          'require-dev': { 'pestphp/pest': '^2.0', 'phpspec/prophecy': '^1.15' }
        })
      };
      const libs = extractTestLibraries('php', manifests);
      expect(libs).toContain('pest');
      expect(libs).toContain('prophecy');
    });

    it('detects fakerphp', () => {
      const manifests = {
        'composer.json': JSON.stringify({
          'require-dev': { 'fakerphp/faker': '^1.20' }
        })
      };
      const libs = extractTestLibraries('php', manifests);
      expect(libs).toContain('faker');
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

    it('detects mockito from pom.xml', () => {
      const manifests = {
        'pom.xml': `<dependency>
  <groupId>org.mockito</groupId>
  <artifactId>mockito-core</artifactId>
  <scope>test</scope>
</dependency>`
      };
      const libs = extractTestLibraries('java', manifests);
      expect(libs).toContain('mockito');
    });

    it('detects mockito from build.gradle', () => {
      const manifests = {
        'build.gradle': `testImplementation 'org.mockito:mockito-core:5.3.1'`
      };
      const libs = extractTestLibraries('java', manifests);
      expect(libs).toContain('mockito');
    });

    it('detects junit from build.gradle.kts', () => {
      const manifests = {
        'build.gradle.kts': `testImplementation("org.junit.jupiter:junit-jupiter:5.9.2")`
      };
      const libs = extractTestLibraries('java', manifests);
      expect(libs).toContain('junit-jupiter');
    });

    it('detects assertj and hamcrest', () => {
      const manifests = {
        'pom.xml': `<artifactId>assertj-core</artifactId>
<artifactId>hamcrest</artifactId>`
      };
      const libs = extractTestLibraries('java', manifests);
      expect(libs).toContain('assertj');
      expect(libs).toContain('hamcrest');
    });
  });

  describe('JavaScript (existing)', () => {
    it('maintains backward compatibility with package.json', () => {
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

    it('detects jest and vitest', () => {
      const manifests = {
        'package.json': JSON.stringify({
          devDependencies: { jest: '^29.0', vitest: '^0.34' }
        })
      };
      const libs = extractTestLibraries('javascript', manifests);
      expect(libs).toContain('jest');
      expect(libs).toContain('vitest');
    });

    it('always includes assert (Node built-in)', () => {
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
    it('defines stdlib libraries for all ecosystems', () => {
      expect(STDLIB_LIBRARIES.python).toContain('unittest');
      expect(STDLIB_LIBRARIES.ruby).toContain('minitest');
      expect(STDLIB_LIBRARIES.elixir).toContain('ExUnit');
      expect(STDLIB_LIBRARIES.javascript).toContain('assert');
    });

    it('includes test/unit for Ruby', () => {
      expect(STDLIB_LIBRARIES.ruby).toContain('test/unit');
    });
  });

  describe('Edge cases', () => {
    it('returns stdlib when manifest is empty', () => {
      const libs = extractTestLibraries('python', {});
      expect(libs).toContain('unittest');
      expect(libs.length).toBe(1);
    });

    it('returns stdlib when manifest is null', () => {
      const libs = extractTestLibraries('ruby', null as unknown as Record<string, string>);
      expect(libs).toContain('minitest');
    });

    it('handles unknown ecosystem gracefully', () => {
      const libs = extractTestLibraries('cobol' as never, {});
      expect(libs).toEqual([]);
    });
  });
});
