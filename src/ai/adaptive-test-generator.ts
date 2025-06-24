/**
 * AdaptiveTestGenerator - Phase 5D Implementation
 * 
 * Generates tests that match repository conventions and detected frameworks.
 * Integrates with TestFrameworkDetector, CoverageAnalyzer, and IssueInterpreter
 * to create contextually appropriate tests.
 */

import { TestFrameworkDetector, type FrameworkInfo as DetectedFramework } from './test-framework-detector.js';
import { CoverageAnalyzer, type CoverageReport } from './coverage-analyzer.js';
import { IssueInterpreter, type InterpretedIssue } from './issue-interpreter.js';
import { VulnerabilityTestGenerator, type VulnerabilityTestSuite, type TestGenerationOptions } from './test-generator.js';
import { VulnerabilityType, type Vulnerability } from '../security/types.js';
import { logger } from '../utils/logger.js';

// Extended vulnerability type that includes file information
interface VulnerabilityWithFile extends Vulnerability {
  file?: string;
}

export interface AdaptiveTestResult {
  success: boolean;
  framework: string;
  testCode: string;
  testSuite?: VulnerabilityTestSuite;
  suggestedFileName?: string;
  notes?: string;
  error?: string;
}

export interface RepoStructure {
  [filePath: string]: string;
}

export class AdaptiveTestGenerator {
  private baseGenerator: VulnerabilityTestGenerator;

  constructor(
    private frameworkDetector: TestFrameworkDetector,
    private coverageAnalyzer: CoverageAnalyzer,
    private issueInterpreter: IssueInterpreter
  ) {
    this.baseGenerator = new VulnerabilityTestGenerator();
  }

  /**
   * Detect frameworks from repository structure
   */
  private async detectFrameworksFromStructure(repoStructure: RepoStructure): Promise<{ frameworks: DetectedFramework[] }> {
    const frameworks: DetectedFramework[] = [];

    // Check all package.json files (including nested ones)
    const packageJsonFiles = Object.keys(repoStructure).filter(path => path.endsWith('package.json'));
    
    for (const packagePath of packageJsonFiles) {
      try {
        const packageJson = JSON.parse(repoStructure[packagePath]);
        const result = await this.frameworkDetector.detectFromPackageJson(packageJson);
        frameworks.push(...result.frameworks);
      } catch (e) {
        // Invalid JSON, skip
      }
    }

    // Check requirements.txt for Python
    if (repoStructure['requirements.txt']) {
      const content = repoStructure['requirements.txt'];
      if (content.includes('pytest')) {
        frameworks.push({
          name: 'pytest',
          version: this.extractVersion(content, 'pytest'),
          type: 'unit',
          confidence: 0.9,
          detectionMethod: 'dependency'
        });
      }
    }

    // Check Gemfile for Ruby
    if (repoStructure['Gemfile']) {
      const content = repoStructure['Gemfile'];
      if (content.includes('minitest')) {
        frameworks.push({
          name: 'minitest',
          version: this.extractVersion(content, 'minitest'),
          type: 'unit',
          confidence: 0.9,
          detectionMethod: 'dependency'
        });
      }
      if (content.includes('rspec')) {
        frameworks.push({
          name: 'rspec',
          version: this.extractVersion(content, 'rspec'),
          type: 'unit',
          confidence: 0.9,
          detectionMethod: 'dependency'
        });
      }
    }

    // Check composer.json for PHP
    if (repoStructure['composer.json']) {
      try {
        const composerJson = JSON.parse(repoStructure['composer.json']);
        const devDeps = composerJson['require-dev'] || {};
        if (devDeps['phpunit/phpunit']) {
          frameworks.push({
            name: 'phpunit',
            version: devDeps['phpunit/phpunit'],
            type: 'unit',
            confidence: 0.95,
            detectionMethod: 'dependency'
          });
        }
      } catch (e) {
        // Invalid JSON, skip
      }
    }

    // Check mix.exs for Elixir
    if (repoStructure['mix.exs']) {
      const content = repoStructure['mix.exs'];
      if (content.includes('ex_unit') || content.includes('ExUnit')) {
        frameworks.push({
          name: 'exunit',
          version: 'builtin',
          type: 'unit',
          confidence: 0.95,
          detectionMethod: 'dependency'
        });
      }
    }

    // Check for config files
    const configFiles = Object.keys(repoStructure).filter(path =>
      path.includes('jest.config') ||
      path.includes('vitest.config') ||
      path.includes('karma.conf') ||
      path.includes('.mocharc')
    );

    if (configFiles.length > 0) {
      const configResult = await this.frameworkDetector.detectFromConfigFiles(configFiles);
      frameworks.push(...configResult.frameworks);
    }

    return { frameworks };
  }

  private extractVersion(content: string, packageName: string): string {
    const versionMatch = content.match(new RegExp(`${packageName}[=~><\\s]+([\\"']?)([\\d\\.\\w-]+)\\1`));
    return versionMatch ? versionMatch[2] : 'unknown';
  }

  /**
   * Generate adaptive tests based on repository context
   */
  async generateAdaptiveTests(
    vulnerability: VulnerabilityWithFile,
    repoStructure: RepoStructure
  ): Promise<AdaptiveTestResult> {
    try {
      logger.info('AdaptiveTestGenerator: generateAdaptiveTests called');
      logger.info('Vulnerability:', JSON.stringify(vulnerability));
      logger.info('RepoStructure keys:', Object.keys(repoStructure));
      
      // 1. Detect test framework from repo structure
      const detectionResult = await this.detectFrameworksFromStructure(repoStructure);
      logger.info('Framework detection result:', JSON.stringify(detectionResult));
      
      const primaryFramework = this.selectPrimaryFramework(detectionResult.frameworks, vulnerability.file);
      logger.info('Selected primary framework:', JSON.stringify(primaryFramework));

      if (!primaryFramework) {
        logger.info('No primary framework detected, generating generic tests');
        return this.generateGenericTests(vulnerability);
      }

      // 2. Analyze existing coverage
      const coverageAnalysis = await this.analyzeCoverage(repoStructure, vulnerability.file || '');

      // 3. Detect testing conventions
      const conventions = this.detectConventions(repoStructure, primaryFramework);

      // 4. Generate framework-specific tests
      const testCode = await this.generateFrameworkSpecificTests(
        vulnerability,
        primaryFramework,
        conventions,
        coverageAnalysis
      );

      // 5. Generate complete test suite
      const testSuite = await this.generateTestSuite(vulnerability, primaryFramework);

      return {
        success: true,
        framework: primaryFramework.name.toLowerCase(),
        testCode,
        testSuite,
        suggestedFileName: this.suggestFileName(vulnerability.file || '', conventions),
        notes: this.generateNotes(primaryFramework, coverageAnalysis, conventions)
      };
    } catch (error) {
      logger.error('Error generating adaptive tests', error as Error);
      return {
        success: false,
        framework: 'unknown',
        testCode: '',
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  /**
   * Select the most appropriate framework for the vulnerability location
   */
  private selectPrimaryFramework(
    frameworks: DetectedFramework[],
    vulnerableFile: string | undefined
  ): DetectedFramework | null {
    if (frameworks.length === 0) return null;

    // If only one framework, use it
    if (frameworks.length === 1) return frameworks[0];

    // For multi-framework repos, choose based on file location
    const fileExt = vulnerableFile?.split('.').pop()?.toLowerCase();
    
    // Map file extensions to likely frameworks
    const extensionPreferences: Record<string, string[]> = {
      'js': ['jest', 'vitest', 'mocha', 'jasmine'],
      'ts': ['jest', 'vitest', 'mocha'],
      'tsx': ['jest', 'vitest', '@testing-library/react'],
      'jsx': ['jest', 'vitest', '@testing-library/react'],
      'py': ['pytest', 'unittest', 'nose2'],
      'rb': ['rspec', 'minitest'],
      'php': ['phpunit', 'pest', 'codeception'],
      'java': ['junit', 'testng'],
      'ex': ['exunit'],
      'exs': ['exunit']
    };

    const preferredFrameworks = extensionPreferences[fileExt || ''] || [];
    
    // Find first matching framework
    for (const preferred of preferredFrameworks) {
      const match = frameworks.find(f => 
        f.name.toLowerCase() === preferred || 
        f.name.toLowerCase().includes(preferred)
      );
      if (match) return match;
    }

    // Default to highest confidence framework
    return frameworks.sort((a, b) => b.confidence - a.confidence)[0];
  }

  /**
   * Analyze existing test coverage
   */
  private async analyzeCoverage(
    repoStructure: RepoStructure,
    vulnerableFile: string
  ): Promise<any> {
    // Find coverage files
    const coverageFiles = Object.keys(repoStructure).filter(path =>
      path.includes('coverage') || path.includes('lcov') || path.includes('.coverage')
    );

    if (coverageFiles.length === 0) {
      return { hasData: false };
    }

    // Parse coverage data based on file type
    let coverageReport: any = null;
    
    for (const file of coverageFiles) {
      const content = repoStructure[file];
      
      if (file.includes('lcov')) {
        coverageReport = await this.coverageAnalyzer.parseLcov(content);
        break;
      } else if (file.includes('.coverage') || file.endsWith('.json')) {
        try {
          coverageReport = await this.coverageAnalyzer.parseCoveragePy(content);
          break;
        } catch (e) {
          // Not coverage.py JSON format
        }
      }
    }

    if (!coverageReport) {
      return { hasData: false };
    }

    // Find coverage gaps
    const gaps = await this.coverageAnalyzer.findCoverageGaps(coverageReport);
    
    // Find coverage for vulnerable file  
    const fileCoverage = coverageReport.files?.find((f: any) => 
      f.path === vulnerableFile || f.path.endsWith(vulnerableFile)
    );

    const recommendations = gaps ? await this.coverageAnalyzer.recommendTestPriorities(gaps) : [];
    
    return {
      hasData: true,
      fileCoverage,
      gaps,
      recommendations
    };
  }

  /**
   * Detect testing conventions from existing tests
   */
  private detectConventions(
    repoStructure: RepoStructure,
    framework: DetectedFramework
  ): any {
    const testFiles = Object.entries(repoStructure).filter(([path]) =>
      path.match(/\.(test|spec)\.(js|ts|jsx|tsx|py|rb|php|java|ex|exs)$/) ||
      path.includes('__tests__') ||
      path.includes('test_') ||
      path.includes('_test')
    );

    const conventions = {
      style: 'unknown',
      assertionStyle: 'unknown',
      fileNaming: 'unknown',
      testDirectory: 'unknown',
      imports: [] as string[],
      helpers: [] as string[]
    };

    // Analyze test files for patterns
    for (const [path, content] of testFiles) {
      // Detect BDD vs TDD style
      if (content.includes('describe(') && content.includes('it(')) {
        conventions.style = 'bdd';
      } else if (content.includes('test(') && !content.includes('describe(')) {
        conventions.style = 'tdd';
      }

      // Detect assertion style
      if (content.includes('expect(') && content.includes('.to.')) {
        conventions.assertionStyle = 'chai-expect';
      } else if (content.includes('expect(') && content.includes('.toBe')) {
        conventions.assertionStyle = 'jest-expect';
      } else if (content.includes('assert.')) {
        conventions.assertionStyle = 'assert';
      } else if (content.includes('_(') && content.includes('.must_') || content.includes('.wont_')) {
        conventions.assertionStyle = 'minitest';
      }

      // Detect file naming
      if (path.includes('.test.')) conventions.fileNaming = 'test';
      else if (path.includes('.spec.')) conventions.fileNaming = 'spec';
      else if (path.includes('__tests__')) conventions.fileNaming = '__tests__';
      else if (path.includes('test_')) conventions.fileNaming = 'test_prefix';

      // Extract imports for helpers
      const importMatches = content.matchAll(/(?:import|require)\s*(?:\{[^}]+\}|\S+)\s*from\s*['"]([^'"]+)['"]/g);
      for (const match of importMatches) {
        if (match[1].includes('helper') || match[1].includes('setup')) {
          conventions.helpers.push(match[0]);
        }
      }

      // Extract setup/teardown patterns
      if (content.includes('beforeEach(setup') || content.includes('afterEach(cleanup')) {
        const setupMatch = content.match(/beforeEach\((\w+)\)/);
        const cleanupMatch = content.match(/afterEach\((\w+)\)/);
        if (setupMatch) conventions.helpers.push(`beforeEach(${setupMatch[1]})`);
        if (cleanupMatch) conventions.helpers.push(`afterEach(${cleanupMatch[1]})`);
      }
    }

    return conventions;
  }

  /**
   * Generate framework-specific test code
   */
  private async generateFrameworkSpecificTests(
    vulnerability: VulnerabilityWithFile,
    framework: DetectedFramework,
    conventions: any,
    coverageAnalysis: any
  ): Promise<string> {
    const frameworkName = framework.name.toLowerCase();
    
    // Get base test structure from VulnerabilityTestGenerator
    const baseOptions: TestGenerationOptions = {
      vulnerabilityType: vulnerability.type.toUpperCase(),
      language: this.getLanguageFromFramework(frameworkName),
      testFramework: this.mapToBaseFramework(frameworkName),
      includeE2E: false
    };

    const baseResult = await this.baseGenerator.generateTestSuite(vulnerability, baseOptions);
    
    if (!baseResult.success || !baseResult.testSuite) {
      logger.error('Base test generation failed', { 
        success: baseResult.success, 
        error: baseResult.error,
        vulnerability: vulnerability.type
      });
      throw new Error(`Failed to generate base test suite: ${baseResult.error || 'Unknown error'}`);
    }

    // Apply framework-specific transformations
    let testCode = this.transformToFrameworkSyntax(
      baseResult.testSuite,
      frameworkName,
      conventions,
      vulnerability
    );

    // Add coverage-aware modifications
    if (coverageAnalysis.hasData && coverageAnalysis.fileCoverage) {
      testCode = this.addCoverageAwareTests(testCode, coverageAnalysis);
    }

    // Add helper imports if detected
    if (conventions.helpers.length > 0) {
      testCode = this.addHelperImports(testCode, conventions.helpers);
    }

    return testCode;
  }

  /**
   * Transform base test suite to framework-specific syntax
   */
  private transformToFrameworkSyntax(
    testSuite: VulnerabilityTestSuite,
    framework: string,
    conventions: any,
    vulnerability: VulnerabilityWithFile
  ): string {
    switch (framework) {
      case 'vitest':
        return this.generateVitestTests(testSuite, conventions, vulnerability);
      case 'mocha':
        return this.generateMochaTests(testSuite, conventions, vulnerability);
      case 'pytest':
        return this.generatePytestTests(testSuite, conventions, vulnerability);
      case 'rspec':
        return this.generateRSpecTests(testSuite, conventions, vulnerability);
      case 'minitest':
        return this.generateMinitestTests(testSuite, conventions, vulnerability);
      case 'exunit':
        return this.generateExUnitTests(testSuite, conventions, vulnerability);
      case 'phpunit':
        return this.generatePHPUnitTests(testSuite, conventions, vulnerability);
      case 'jest':
        return this.generateJestTests(testSuite, conventions, vulnerability);
      default:
        return this.generateGenericTestCode(testSuite, vulnerability);
    }
  }

  /**
   * Generate Vitest-specific tests
   */
  private generateVitestTests(
    testSuite: VulnerabilityTestSuite,
    conventions: any,
    vulnerability: VulnerabilityWithFile
  ): string {
    const componentName = vulnerability.file?.split('/').pop()?.replace(/\.(tsx?|jsx?)$/, '') || 'Component';
    const isReact = vulnerability.file?.endsWith('.tsx') || vulnerability.file?.endsWith('.jsx') || false;
    
    // Extract just the test body from the testCode (remove the test wrapper)
    const extractTestBody = (testCode: string) => {
      // Remove the test() wrapper if present
      const match = testCode.match(/test\([^{]+\{([\s\S]*)\}\);?$/);
      return match ? match[1].trim() : testCode;
    };
    
    const imports = isReact 
      ? `import { describe, test, expect, beforeEach, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { ${componentName} } from "${this.getRelativeImportPath(vulnerability.file || '')}";`
      : `import { describe, test, expect } from "vitest";
import { ${componentName} } from "${this.getRelativeImportPath(vulnerability.file || '')}";`;

    return `${imports}

describe("${componentName} ${vulnerability.type} vulnerability tests", () => {
  ${conventions.helpers.length > 0 ? conventions.helpers.join('\n  ') : ''}

  test("${testSuite.red.testName}", async () => {
    // RED: Demonstrate vulnerability exists
    const maliciousInput = "${testSuite.red.attackVector}";
    ${extractTestBody(testSuite.red.testCode)}
  });

  test("${testSuite.green.testName}", async () => {
    // GREEN: Verify fix prevents vulnerability  
    const maliciousInput = "${testSuite.red.attackVector}";
    const safeInput = "${testSuite.green.validInput}";
    ${extractTestBody(testSuite.green.testCode)}
  });

  test("${testSuite.refactor.testName}", async () => {
    // REFACTOR: Ensure functionality is maintained
    ${extractTestBody(testSuite.refactor.testCode)}
  });
});`;
  }

  /**
   * Generate Mocha + Chai tests
   */
  private generateMochaTests(
    testSuite: VulnerabilityTestSuite,
    conventions: any,
    vulnerability: VulnerabilityWithFile
  ): string {
    const moduleName = vulnerability.file?.split('/').pop()?.replace(/\.js$/, '') || 'module';
    const assertionLib = conventions.assertionStyle === 'assert' ? 'assert' : 'chai';
    
    const imports = assertionLib === 'chai' 
      ? 'const { expect } = require("chai");'
      : 'const assert = require("assert");';

    const assertion = assertionLib === 'chai'
      ? (positive: boolean, actual: string, expected: string) => 
          positive ? `expect(${actual}).to.include(${expected})` : `expect(${actual}).to.not.include(${expected})`
      : (positive: boolean, actual: string, expected: string) =>
          positive ? `assert(${actual}.includes(${expected}))` : `assert(!${actual}.includes(${expected}))`;

    // Mocha typically uses 'it' for BDD style
    const testFn = 'it';

    return `${imports}
const { ${moduleName} } = require("${this.getRelativeRequirePath(vulnerability.file || '')}");

describe("${moduleName.charAt(0).toUpperCase() + moduleName.slice(1)} ${vulnerability.type === VulnerabilityType.SQL_INJECTION ? 'SQL injection' : vulnerability.type.replace(/_/g, ' ').toLowerCase()} tests", () => {
  ${testFn}("should be vulnerable to ${vulnerability.type === VulnerabilityType.SQL_INJECTION ? 'SQL injection' : vulnerability.type.replace(/_/g, ' ').toLowerCase()} (RED)", async () => {
    // RED: Demonstrate vulnerability exists
    const maliciousInput = "${testSuite.red.attackVector}";
    const result = await ${moduleName}(maliciousInput);
    ${assertion(false, 'result', '"syntax error"')};
  });

  ${testFn}("should prevent ${vulnerability.type === VulnerabilityType.SQL_INJECTION ? 'SQL injection' : vulnerability.type.replace(/_/g, ' ').toLowerCase()} (GREEN)", async () => {
    // GREEN: Verify fix prevents vulnerability
    const maliciousInput = "${testSuite.red.attackVector}";
    const result = await ${moduleName}(maliciousInput);
    ${assertion(false, 'result', '"table"')};
  });

  ${testFn}("${testSuite.refactor.testName}", async () => {
    // REFACTOR: Ensure functionality is maintained
    const validInput = "${testSuite.green.validInput}";
    const result = await ${moduleName}(validInput);
    ${assertion(true, 'result', '"success"')};
  });
});`;
  }

  /**
   * Generate pytest tests
   */
  private generatePytestTests(
    testSuite: VulnerabilityTestSuite,
    conventions: any,
    vulnerability: VulnerabilityWithFile
  ): string {
    const moduleName = vulnerability.file?.split('/').pop()?.replace(/\.py$/, '') || 'module';
    const className = moduleName.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join('');

    return `import pytest
from ${vulnerability.file?.replace(/\.py$/, '').replace(/\//g, '.') || 'module'} import *

@pytest.mark.security
class Test${className}${vulnerability.type.replace(/_/g, '')}:
    """Tests for ${vulnerability.type} vulnerability in ${moduleName}"""

    def test_${vulnerability.type.toLowerCase()}_vulnerability_red(self):
        """${testSuite.red.testName}"""
        # RED: Demonstrate vulnerability exists
        malicious_input = "${testSuite.red.attackVector}"
        result = ${moduleName}(malicious_input)
        assert "root" not in result
        assert "permission denied" not in result.lower()

    def test_${vulnerability.type.toLowerCase()}_vulnerability_green(self):
        """${testSuite.green.testName}"""
        # GREEN: Verify fix prevents vulnerability
        malicious_input = "${testSuite.red.attackVector}"
        with pytest.raises(ValueError):
            ${moduleName}(malicious_input)

    def test_${vulnerability.type.toLowerCase()}_functionality_maintained(self):
        """${testSuite.refactor.testName}"""
        # REFACTOR: Ensure functionality is maintained
        valid_input = "${testSuite.green.validInput}"
        result = ${moduleName}(valid_input)
        assert result is not None
        assert "error" not in str(result).lower()`;
  }

  /**
   * Generate Minitest tests
   */
  private generateMinitestTests(
    testSuite: VulnerabilityTestSuite,
    conventions: any,
    vulnerability: VulnerabilityWithFile
  ): string {
    const className = vulnerability.file
      ?.split('/')
      .pop()
      ?.replace(/\.rb$/, '')
      .split('_')
      .map(w => w.charAt(0).toUpperCase() + w.slice(1))
      .join('') || 'Module';

    return `require "minitest/autorun"
require "minitest/spec"
require_relative "${this.getRelativeRequirePath(vulnerability.file || '')}"

describe ${className} do
  describe "${vulnerability.type} vulnerability tests" do
    it "must be vulnerable to ${vulnerability.type.toLowerCase()} (RED)" do
      # RED: Demonstrate vulnerability exists
      malicious_input = "${testSuite.red.attackVector}"
      result = ${className}.new.process(malicious_input)
      _(result).wont_include "Permission denied"
      _(result).wont_include "syntax error"
    end

    it "must prevent ${vulnerability.type.toLowerCase()} (GREEN)" do
      # GREEN: Verify fix prevents vulnerability
      malicious_input = "${testSuite.red.attackVector}"
      _ { ${className}.new.process(malicious_input) }.must_raise SecurityError
    end

    it "must maintain functionality (REFACTOR)" do
      # REFACTOR: Ensure functionality is maintained
      valid_input = "${testSuite.green.validInput}"
      result = ${className}.new.process(valid_input)
      _(result).must_be_kind_of String
      _(result).wont_be_empty
    end
  end
end`;
  }

  /**
   * Generate RSpec tests
   */
  private generateRSpecTests(
    testSuite: VulnerabilityTestSuite,
    conventions: any,
    vulnerability: VulnerabilityWithFile
  ): string {
    const className = vulnerability.file
      ?.split('/')
      .pop()
      ?.replace(/\.rb$/, '')
      .split('_')
      .map(w => w.charAt(0).toUpperCase() + w.slice(1))
      .join('') || 'Module';

    const controllerName = vulnerability.file?.includes('controller') ? className : `${className}Controller`;
    
    return `require 'rails_helper'

RSpec.describe ${controllerName}, type: :controller do
  describe "${vulnerability.type} vulnerability tests" do
    context "when vulnerable to ${vulnerability.type.toLowerCase()} (RED)" do
      it "should be exploitable with malicious input" do
        # RED: Demonstrate vulnerability exists
        malicious_input = "${testSuite.red.attackVector}"
        
        # For SQL injection in Rails controller
        params = { user: { id: malicious_input } }
        
        # This test should pass BEFORE the fix
        expect {
          post :update, params: params
        }.not_to raise_error
        
        # The vulnerability allows SQL injection
        expect(response).to have_http_status(:ok)
      end
    end

    context "when protected against ${vulnerability.type.toLowerCase()} (GREEN)" do
      it "should prevent exploitation attempts" do
        # GREEN: Verify fix prevents vulnerability
        malicious_input = "${testSuite.red.attackVector}"
        
        # For SQL injection in Rails controller
        params = { user: { id: malicious_input } }
        
        # After fix, this should raise an error or sanitize input
        post :update, params: params
        
        # Either it should return an error or sanitize the input
        expect(response).to have_http_status(:bad_request).or have_http_status(:unprocessable_entity)
      end
    end

    context "when handling valid input (REFACTOR)" do
      it "should maintain normal functionality" do
        # REFACTOR: Ensure functionality is maintained
        valid_input = "${testSuite.green.validInput}"
        
        # For normal user update
        params = { user: { id: valid_input } }
        
        post :update, params: params
        
        expect(response).to have_http_status(:ok)
        expect(assigns(:user)).not_to be_nil
      end
    end
  end
end`;
  }

  /**
   * Generate ExUnit tests
   */
  private generateExUnitTests(
    testSuite: VulnerabilityTestSuite,
    conventions: any,
    vulnerability: VulnerabilityWithFile
  ): string {
    const moduleName = vulnerability.file
      ?.split('/')
      .pop()
      ?.replace(/\.ex$/, '')
      .split('_')
      .map(w => w.charAt(0).toUpperCase() + w.slice(1))
      .join('') || 'Module';

    return `defmodule ${moduleName}Test do
  use ExUnit.Case
  alias ${moduleName}

  describe "${vulnerability.type.toLowerCase()} vulnerability" do
    test "vulnerable to malicious payload (RED)" do
      # RED: Demonstrate vulnerability exists
      malicious_input = "${testSuite.red.attackVector}"
      assert {:ok, result} = ${moduleName}.process(malicious_input)
      refute String.contains?(result, "error")
    end

    test "prevents ${vulnerability.type.toLowerCase()} attack (GREEN)" do
      # GREEN: Verify fix prevents vulnerability
      malicious_input = "${testSuite.red.attackVector}"
      assert {:error, _} = ${moduleName}.process(malicious_input)
    end

    test "maintains normal functionality (REFACTOR)" do
      # REFACTOR: Ensure functionality is maintained
      valid_input = "${testSuite.green.validInput}"
      assert {:ok, result} = ${moduleName}.process(valid_input)
      assert is_binary(result)
    end
  end
end`;
  }

  /**
   * Generate PHPUnit tests
   */
  private generatePHPUnitTests(
    testSuite: VulnerabilityTestSuite,
    conventions: any,
    vulnerability: VulnerabilityWithFile
  ): string {
    const className = vulnerability.file
      ?.split('/')
      .pop()
      ?.replace(/\.php$/, '') || 'Class';

    return `<?php
use PHPUnit\\Framework\\TestCase;
use App\\${className};

/**
 * @group security
 */
class ${className}${vulnerability.type.replace(/_/g, '')}Test extends TestCase
{
    private $instance;

    protected function setUp(): void
    {
        $this->instance = new ${className}();
    }

    public function test${vulnerability.type.replace(/_/g, '')}VulnerabilityRed()
    {
        // RED: Demonstrate vulnerability exists
        $maliciousInput = '${testSuite.red.attackVector}';
        $result = $this->instance->process($maliciousInput);
        
        $this->assertStringNotContainsString('<script>', $result);
        $this->assertStringNotContainsString('error', $result);
    }

    public function test${vulnerability.type.replace(/_/g, '')}VulnerabilityGreen()
    {
        // GREEN: Verify fix prevents vulnerability
        $maliciousInput = '${testSuite.red.attackVector}';
        
        $this->expectException(SecurityException::class);
        $this->instance->process($maliciousInput);
    }

    public function test${vulnerability.type.replace(/_/g, '')}FunctionalityMaintained()
    {
        // REFACTOR: Ensure functionality is maintained
        $validInput = '${testSuite.green.validInput}';
        $result = $this->instance->process($validInput);
        
        $this->assertNotEmpty($result);
        $this->assertIsString($result);
    }
}`;
  }

  /**
   * Generate Jest tests (default for JavaScript)
   */
  private generateJestTests(
    testSuite: VulnerabilityTestSuite,
    conventions: any,
    vulnerability: VulnerabilityWithFile
  ): string {
    const moduleName = vulnerability.file?.split('/').pop()?.replace(/\.[jt]sx?$/, '') || 'module';
    
    const testWrapper = conventions.style === 'bdd' ? 'describe' : '';
    const testKeyword = conventions.style === 'bdd' ? 'it' : 'test';

    const imports = `const { ${moduleName} } = require('${this.getRelativeRequirePath(vulnerability.file || '')}');`;

    const tests = `
${testWrapper ? `describe('${moduleName} ${vulnerability.type} tests', () => {` : ''}
  ${testKeyword}('${testSuite.red.testName}', async () => {
    // RED: Demonstrate vulnerability exists
    const maliciousInput = '${testSuite.red.attackVector}';
    const result = await ${moduleName}(maliciousInput);
    expect(result).not.toContain('error');
  });

  ${testKeyword}('${testSuite.green.testName}', async () => {
    // GREEN: Verify fix prevents vulnerability
    const maliciousInput = '${testSuite.red.attackVector}';
    await expect(${moduleName}(maliciousInput)).rejects.toThrow();
  });

  ${testKeyword}('${testSuite.refactor.testName}', async () => {
    // REFACTOR: Ensure functionality is maintained
    const validInput = '${testSuite.green.validInput}';
    const result = await ${moduleName}(validInput);
    expect(result).toBeTruthy();
  });
${testWrapper ? '});' : ''}`;

    return imports + '\n' + tests;
  }

  /**
   * Generate generic test code when framework is unknown
   */
  private generateGenericTestCode(
    testSuite: VulnerabilityTestSuite,
    vulnerability: VulnerabilityWithFile
  ): string {
    return `// Generic test template - adapt to your test framework
// File: ${vulnerability.file}
// Vulnerability: ${vulnerability.type}

// RED Test: ${testSuite.red.testName}
// Purpose: Demonstrate the vulnerability exists
function testVulnerabilityExists() {
  const maliciousInput = "${testSuite.red.attackVector}";
  // TODO: Call vulnerable function with malicious input
  // TODO: Assert that attack succeeds (should fail when fixed)
}

// GREEN Test: ${testSuite.green.testName}
// Purpose: Verify the fix prevents the vulnerability
function testVulnerabilityFixed() {
  const maliciousInput = "${testSuite.red.attackVector}";
  // TODO: Call fixed function with malicious input
  // TODO: Assert that attack is prevented
}

// REFACTOR Test: ${testSuite.refactor.testName}
// Purpose: Ensure normal functionality still works
function testFunctionalityMaintained() {
  const validInput = "${testSuite.green.validInput}";
  // TODO: Call function with valid input
  // TODO: Assert expected behavior works correctly
}`;
  }

  /**
   * Generate generic tests when no framework is detected
   */
  private async generateGenericTests(vulnerability: VulnerabilityWithFile): Promise<AdaptiveTestResult> {
    const baseOptions: TestGenerationOptions = {
      vulnerabilityType: vulnerability.type,
      language: 'javascript',
      testFramework: 'bun',
      includeE2E: false
    };

    const baseResult = await this.baseGenerator.generateTestSuite(vulnerability, baseOptions);

    return {
      success: true,
      framework: 'generic',
      testCode: '// Generic test template\n' + this.generateGenericTestCode(baseResult.testSuite!, vulnerability),
      testSuite: baseResult.testSuite || undefined,
      notes: 'No test framework detected, using generic template'
    };
  }

  /**
   * Generate test suite using base generator
   */
  private async generateTestSuite(
    vulnerability: VulnerabilityWithFile,
    framework: DetectedFramework
  ): Promise<VulnerabilityTestSuite> {
    const options: TestGenerationOptions = {
      vulnerabilityType: vulnerability.type.toUpperCase(),
      language: this.getLanguageFromFramework(framework.name),
      testFramework: this.mapToBaseFramework(framework.name),
      includeE2E: false
    };

    const result = await this.baseGenerator.generateTestSuite(vulnerability, options);
    
    if (!result.success || !result.testSuite) {
      logger.error('Test suite generation failed in generateTestSuite', {
        success: result.success,
        error: result.error,
        vulnerabilityType: vulnerability.type
      });
      throw new Error(`Failed to generate test suite: ${result.error || 'Unknown error'}`);
    }

    return result.testSuite;
  }

  /**
   * Suggest test file name based on conventions
   */
  private suggestFileName(vulnerableFile: string, conventions: any): string {
    const dir = vulnerableFile.substring(0, vulnerableFile.lastIndexOf('/'));
    const fileName = vulnerableFile.substring(vulnerableFile.lastIndexOf('/') + 1);
    const baseName = fileName.substring(0, fileName.lastIndexOf('.'));
    const ext = fileName.substring(fileName.lastIndexOf('.'));

    switch (conventions.fileNaming) {
      case 'test':
        return `${dir}/${baseName}.test${ext}`;
      case 'spec':
        return `${dir}/${baseName}.spec${ext}`;
      case '__tests__':
        return `${dir}/__tests__/${baseName}${ext}`;
      case 'test_prefix':
        return `${dir}/test_${baseName}${ext}`;
      default:
        return `${dir}/${baseName}.test${ext}`;
    }
  }

  /**
   * Add coverage-aware test modifications
   */
  private addCoverageAwareTests(testCode: string, coverageAnalysis: any): string {
    if (!coverageAnalysis.fileCoverage || coverageAnalysis.fileCoverage.functions.length === 0) {
      return testCode;
    }

    // Find uncovered functions
    const uncoveredFunctions = coverageAnalysis.fileCoverage.functions
      .filter((f: any) => f.hits === 0)
      .map((f: any) => f.name);

    if (uncoveredFunctions.length > 0) {
      const comment = `\n// Note: Focusing on uncovered functions: ${uncoveredFunctions.join(', ')}\n`;
      return comment + testCode;
    }

    return testCode;
  }

  /**
   * Add helper imports to test code
   */
  private addHelperImports(testCode: string, helpers: string[]): string {
    const imports = helpers
      .filter(h => h.includes('import') || h.includes('require'))
      .join('\n');
    
    const setupTeardown = helpers
      .filter(h => h.includes('beforeEach') || h.includes('afterEach'))
      .join('\n  ');

    if (imports) {
      testCode = imports + '\n\n' + testCode;
    }

    if (setupTeardown) {
      // Insert setup/teardown after describe line
      testCode = testCode.replace(
        /(describe\([^{]+\{)/,
        `$1\n  ${setupTeardown}\n`
      );
    }

    return testCode;
  }

  /**
   * Generate notes about the generation process
   */
  private generateNotes(
    framework: DetectedFramework,
    coverageAnalysis: any,
    conventions: any
  ): string {
    const notes: string[] = [];

    notes.push(`Detected ${framework.name} v${framework.version || 'unknown'}`);
    
    if (coverageAnalysis.hasData) {
      notes.push('Coverage data available');
      if (coverageAnalysis.fileCoverage) {
        const coverage = coverageAnalysis.fileCoverage.lines?.percentage || 
                        coverageAnalysis.fileCoverage.coverage || 
                        'unknown';
        notes.push(`File coverage: ${coverage}%`);
      }
      if (coverageAnalysis.gaps?.recommendations?.length > 0) {
        notes.push('Focused on uncovered functions');
      }
    } else {
      notes.push('No coverage data available');
    }

    if (conventions.style !== 'unknown') {
      notes.push(`Using ${conventions.style.toUpperCase()} style`);
    }

    if (conventions.assertionStyle !== 'unknown') {
      notes.push(`Using ${conventions.assertionStyle} assertions`);
    }

    return notes.join('; ');
  }

  /**
   * Helper methods for language/framework mapping
   */
  private getLanguageFromFramework(framework: string): TestGenerationOptions['language'] {
    const languageMap: Record<string, TestGenerationOptions['language']> = {
      'jest': 'javascript',
      'vitest': 'typescript',
      'mocha': 'javascript',
      'jasmine': 'javascript',
      'pytest': 'python',
      'unittest': 'python',
      'rspec': 'ruby',
      'minitest': 'ruby',
      'phpunit': 'php',
      'junit': 'java',
      'exunit': 'javascript', // Elixir not in base options, using JS
    };

    return languageMap[framework.toLowerCase()] || 'javascript';
  }

  private mapToBaseFramework(framework: string): TestGenerationOptions['testFramework'] {
    const frameworkMap: Record<string, TestGenerationOptions['testFramework']> = {
      'jest': 'jest',
      'vitest': 'jest', // Similar syntax
      'mocha': 'mocha',
      'jasmine': 'mocha', // Similar syntax
      'cypress': 'cypress',
      // Others map to closest equivalent
      'pytest': 'jest',
      'minitest': 'mocha',
      'phpunit': 'jest',
      'exunit': 'mocha'
    };

    return frameworkMap[framework.toLowerCase()] || 'bun';
  }

  private getRelativeImportPath(filePath: string): string {
    // Convert absolute path to relative import
    return filePath.replace(/\.tsx?$/, '').replace(/^src\//, '../');
  }

  private getRelativeRequirePath(filePath: string): string {
    // Convert to relative require path
    return './' + filePath.replace(/\.(js|ts|rb|py|php)$/, '');
  }
}