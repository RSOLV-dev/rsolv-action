/**
 * AI-powered test generator that creates context-aware tests for any vulnerability type
 */

import { Vulnerability } from '../security/types.js';
import { TestGenerationOptions, VulnerabilityTestSuite } from './test-generator.js';
import { logger } from '../utils/logger.js';
import { AiClient, getAiClient } from './client.js';
import { AIConfig } from './types.js';
import { AiProviderConfig } from '../types/index.js';

export interface AITestGenerationResult {
  success: boolean;
  testSuite?: VulnerabilityTestSuite;
  testCode: string;
  framework: string;
  error?: string;
}

export class AITestGenerator {
  private aiClient: AiClient | null = null;
  private aiConfig: AIConfig;

  constructor(aiConfig: AIConfig) {
    this.aiConfig = aiConfig;
  }

  private async getClient(): Promise<AiClient> {
    if (!this.aiClient) {
      // Convert AIConfig to AiProviderConfig
      const providerConfig: AiProviderConfig = {
        provider: this.aiConfig.provider || 'anthropic',
        apiKey: this.aiConfig.apiKey || '',
        model: this.aiConfig.model || 'claude-3-sonnet',
        temperature: this.aiConfig.temperature,
        maxTokens: this.aiConfig.maxTokens,
        useVendedCredentials: this.aiConfig.useVendedCredentials
      };
      
      this.aiClient = await getAiClient(providerConfig);
    }
    return this.aiClient;
  }

  async generateTests(
    vulnerability: Vulnerability,
    options: TestGenerationOptions,
    fileContent?: string
  ): Promise<AITestGenerationResult> {
    try {
      logger.info(`Generating AI-powered tests for ${vulnerability.type} vulnerability`);

      const prompt = this.constructTestGenerationPrompt(vulnerability, options, fileContent);
      const client = await this.getClient();
      const response = await client.complete(prompt);

      // Parse the AI response to extract test suite
      const testSuite = this.parseTestSuite(response);

      if (!testSuite) {
        // Don't throw - return failure gracefully to avoid retries
        logger.warn('Failed to parse test suite from AI response, returning failure');
        return {
          success: false,
          testCode: '',
          framework: options.testFramework || 'jest',
          error: 'Failed to parse AI response - response may be truncated'
        };
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
IMPORTANT: Return ONLY valid JSON. Keep test code CONCISE (max 10-15 lines per test).
Focus on the core vulnerability check, not elaborate setup.

Return EXACTLY this JSON structure (no markdown, no backticks):
{
  "red": {
    "testName": "short descriptive name",
    "testCode": "concise test code (10-15 lines max)",
    "attackVector": "malicious input",
    "expectedBehavior": "brief description"
  },
  "green": {
    "testName": "short descriptive name",
    "testCode": "concise test code (10-15 lines max)",
    "validInput": "safe input",
    "expectedBehavior": "brief description"
  },
  "refactor": {
    "testName": "short descriptive name",
    "testCode": "concise test code (10-15 lines max)",
    "testCases": ["scenario1", "scenario2"],
    "expectedBehavior": "brief description"
  }
}

Keep ALL strings properly escaped. Avoid long test code.
Return ONLY the JSON, no explanations.`;
  }

  private parseTestSuite(aiResponse: string): VulnerabilityTestSuite | null {
    try {
      let jsonString: string | null = null;

      // Try multiple extraction strategies
      // 1. Check for markdown code blocks with json
      const markdownJsonMatch = aiResponse.match(/```json\s*([\s\S]*?)```/);
      if (markdownJsonMatch) {
        jsonString = markdownJsonMatch[1].trim();
      }

      // 2. Check for any markdown code blocks
      if (!jsonString) {
        const markdownMatch = aiResponse.match(/```[\s\S]*?\n([\s\S]*?)```/);
        if (markdownMatch) {
          jsonString = markdownMatch[1].trim();
        }
      }

      // 3. Try to extract raw JSON object
      if (!jsonString) {
        const jsonMatch = aiResponse.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          jsonString = jsonMatch[0];
        }
      }

      // 4. If response looks like pure JSON, use it directly
      if (!jsonString && aiResponse.trim().startsWith('{')) {
        jsonString = aiResponse.trim();
      }

      if (!jsonString) {
        logger.error('No JSON found in AI response. Response preview:', aiResponse.substring(0, 200));
        return null;
      }

      // Clean up common issues
      jsonString = jsonString
        .replace(/^\s*```\s*json?\s*/gm, '') // Remove stray markdown markers
        .replace(/\s*```\s*$/gm, '')
        .trim();

      // Attempt to fix common JSON issues before parsing
      // Handle truncated responses by closing unclosed structures
      let openBraces = (jsonString.match(/\{/g) || []).length;
      let closeBraces = (jsonString.match(/\}/g) || []).length;
      if (openBraces > closeBraces) {
        logger.warn(`Fixing unclosed JSON structure: ${openBraces} open, ${closeBraces} closed`);
        // Add missing closing braces
        jsonString += '}'.repeat(openBraces - closeBraces);
      }

      // If the JSON appears truncated (ends mid-string), try to close it
      if (jsonString.match(/"[^"]*$/) && !jsonString.endsWith('"}')) {
        logger.warn('JSON appears truncated mid-string, attempting to close');
        jsonString += '"}}}';
      }

      let parsed;
      try {
        parsed = JSON.parse(jsonString);
      } catch (parseError) {
        logger.error('Failed to parse JSON after cleanup attempts:', parseError);
        logger.debug('Attempted to parse:', jsonString.substring(0, 500));
        return null;
      }
      
      // Validate the structure
      if (!parsed.red || !parsed.green || !parsed.refactor) {
        logger.error('Invalid test suite structure. Keys found:', Object.keys(parsed));
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
      logger.error('Failed to parse AI response:', error);
      logger.debug('Response that failed to parse:', aiResponse.substring(0, 500));
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