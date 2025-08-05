/**
 * AI-powered test generator that creates context-aware tests for any vulnerability type
 */

import { Vulnerability } from '../security/types.js';
import { TestGenerationOptions, VulnerabilityTestSuite } from './test-generator.js';
import { logger } from '../utils/logger.js';
import { AIClient } from './client.js';
import { AIConfig } from './types.js';

export interface AITestGenerationResult {
  success: boolean;
  testSuite?: VulnerabilityTestSuite;
  testCode: string;
  framework: string;
  error?: string;
}

export class AITestGenerator {
  private aiClient: AIClient;

  constructor(aiConfig: AIConfig) {
    this.aiClient = new AIClient(aiConfig);
  }

  async generateTests(
    vulnerability: Vulnerability,
    options: TestGenerationOptions,
    fileContent?: string
  ): Promise<AITestGenerationResult> {
    try {
      logger.info(`Generating AI-powered tests for ${vulnerability.type} vulnerability`);

      const prompt = this.constructTestGenerationPrompt(vulnerability, options, fileContent);
      const response = await this.aiClient.complete(prompt);
      
      // Parse the AI response to extract test suite
      const testSuite = this.parseTestSuite(response.content);
      
      if (!testSuite) {
        throw new Error('Failed to parse test suite from AI response');
      }

      // Generate complete test code
      const testCode = this.generateTestCode(testSuite, options);

      return {
        success: true,
        testSuite,
        testCode,
        framework: options.testFramework || 'jest'
      };
    } catch (error) {
      logger.error('AI test generation failed', error as Error);
      return {
        success: false,
        testCode: '',
        framework: options.testFramework || 'jest',
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  private constructTestGenerationPrompt(
    vulnerability: Vulnerability,
    options: TestGenerationOptions,
    fileContent?: string
  ): string {
    return `You are an expert security test engineer. Generate comprehensive tests for a security vulnerability using Test-Driven Development (TDD) methodology.

## Vulnerability Details:
- Type: ${vulnerability.type}
- Severity: ${vulnerability.severity}
- File: ${vulnerability.filePath || 'unknown'}
- Line: ${vulnerability.line}
- Description: ${vulnerability.description}
- Message: ${vulnerability.message}
${vulnerability.remediation ? `- Remediation: ${vulnerability.remediation}` : ''}

## Test Requirements:
1. Generate THREE test cases following TDD red-green-refactor:
   - RED test: Proves the vulnerability exists (should FAIL on vulnerable code, PASS on fixed code)
   - GREEN test: Validates the fix works (should FAIL on vulnerable code, PASS on fixed code)
   - REFACTOR test: Ensures functionality is preserved (should PASS on both)

2. Use ${options.language || 'javascript'} with ${options.testFramework || 'jest'} framework
3. Tests must be executable and use actual attack vectors
4. Include proper assertions to validate security

${fileContent ? `## Vulnerable Code:\n\`\`\`${options.language}\n${fileContent}\n\`\`\`` : ''}

## Response Format:
Provide a JSON object with this structure:
{
  "red": {
    "testName": "descriptive test name",
    "testCode": "complete executable test code",
    "attackVector": "actual malicious input used",
    "expectedBehavior": "what should happen"
  },
  "green": {
    "testName": "descriptive test name", 
    "testCode": "complete executable test code",
    "validInput": "safe input example",
    "expectedBehavior": "what should happen"
  },
  "refactor": {
    "testName": "descriptive test name",
    "testCode": "complete executable test code",
    "testCases": ["list of functional scenarios to test"],
    "expectedBehavior": "what should happen"
  }
}

Generate executable test code that can be run immediately, not pseudo-code or descriptions.`;
  }

  private parseTestSuite(aiResponse: string): VulnerabilityTestSuite | null {
    try {
      // Extract JSON from the response
      const jsonMatch = aiResponse.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        logger.error('No JSON found in AI response');
        return null;
      }

      const parsed = JSON.parse(jsonMatch[0]);
      
      // Validate the structure
      if (!parsed.red || !parsed.green || !parsed.refactor) {
        logger.error('Invalid test suite structure');
        return null;
      }

      return {
        red: {
          testName: parsed.red.testName,
          testCode: parsed.red.testCode,
          attackVector: parsed.red.attackVector,
          expectedBehavior: parsed.red.expectedBehavior
        },
        green: {
          testName: parsed.green.testName,
          testCode: parsed.green.testCode,
          validInput: parsed.green.validInput,
          expectedBehavior: parsed.green.expectedBehavior
        },
        refactor: {
          testName: parsed.refactor.testName,
          testCode: parsed.refactor.testCode,
          functionalValidation: parsed.refactor.testCases || [],
          expectedBehavior: parsed.refactor.expectedBehavior
        }
      };
    } catch (error) {
      logger.error('Failed to parse AI response', error);
      return null;
    }
  }

  private generateTestCode(testSuite: VulnerabilityTestSuite, options: TestGenerationOptions): string {
    const framework = options.testFramework || 'jest';
    const language = options.language || 'javascript';

    if (language === 'javascript' || language === 'typescript') {
      return this.generateJavaScriptTests(testSuite, framework);
    } else if (language === 'python') {
      return this.generatePythonTests(testSuite);
    } else if (language === 'ruby') {
      return this.generateRubyTests(testSuite);
    } else if (language === 'php') {
      return this.generatePHPTests(testSuite);
    } else if (language === 'elixir') {
      return this.generateElixirTests(testSuite);
    }

    // Default to JavaScript
    return this.generateJavaScriptTests(testSuite, framework);
  }

  private generateJavaScriptTests(testSuite: VulnerabilityTestSuite, framework: string): string {
    if (framework === 'jest' || framework === 'mocha' || framework === 'vitest') {
      return `
const { expect } = require('chai');

describe('Security Vulnerability Tests', () => {
  // RED Test - Proves vulnerability exists
  ${testSuite.red.testCode}

  // GREEN Test - Validates fix
  ${testSuite.green.testCode}

  // REFACTOR Test - Ensures functionality
  ${testSuite.refactor.testCode}
});`;
    }

    // Default test structure
    return `
// Security Tests
${testSuite.red.testCode}
${testSuite.green.testCode}
${testSuite.refactor.testCode}`;
  }

  private generatePythonTests(testSuite: VulnerabilityTestSuite): string {
    return `
import unittest

class SecurityVulnerabilityTests(unittest.TestCase):
    # RED Test - Proves vulnerability exists
    ${testSuite.red.testCode}
    
    # GREEN Test - Validates fix
    ${testSuite.green.testCode}
    
    # REFACTOR Test - Ensures functionality
    ${testSuite.refactor.testCode}

if __name__ == '__main__':
    unittest.main()`;
  }

  private generateRubyTests(testSuite: VulnerabilityTestSuite): string {
    return `
require 'rspec'

RSpec.describe 'Security Vulnerability Tests' do
  # RED Test - Proves vulnerability exists
  ${testSuite.red.testCode}
  
  # GREEN Test - Validates fix
  ${testSuite.green.testCode}
  
  # REFACTOR Test - Ensures functionality
  ${testSuite.refactor.testCode}
end`;
  }

  private generatePHPTests(testSuite: VulnerabilityTestSuite): string {
    return `
<?php
use PHPUnit\\Framework\\TestCase;

class SecurityVulnerabilityTest extends TestCase {
    // RED Test - Proves vulnerability exists
    ${testSuite.red.testCode}
    
    // GREEN Test - Validates fix
    ${testSuite.green.testCode}
    
    // REFACTOR Test - Ensures functionality
    ${testSuite.refactor.testCode}
}`;
  }

  private generateElixirTests(testSuite: VulnerabilityTestSuite): string {
    return `
defmodule SecurityVulnerabilityTest do
  use ExUnit.Case
  
  # RED Test - Proves vulnerability exists
  ${testSuite.red.testCode}
  
  # GREEN Test - Validates fix
  ${testSuite.green.testCode}
  
  # REFACTOR Test - Ensures functionality
  ${testSuite.refactor.testCode}
end`;
  }
}