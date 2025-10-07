/**
 * AI-powered test generator that creates context-aware tests for any vulnerability type
 */

import { Vulnerability } from '../security/types.js';
import { TestGenerationOptions, VulnerabilityTestSuite } from './test-generator.js';
import { logger } from '../utils/logger.js';
import { AiClient, getAiClient } from './client.js';
import { AIConfig } from './types.js';
import { AiProviderConfig } from '../types/index.js';
import { getTestGenerationTokenLimit } from './token-utils.js';

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
      // Override maxTokens for test generation to handle complex JSON responses
      const providerConfig: AiProviderConfig = {
        provider: this.aiConfig.provider || 'anthropic',
        apiKey: this.aiConfig.apiKey || '',
        model: this.aiConfig.model || 'claude-3-sonnet',
        temperature: this.aiConfig.temperature,
        maxTokens: this.aiConfig.maxTokens, // Will be resolved by token-utils during completion
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
      // Use DRY token resolution specifically for test generation
      // Don't pass maxTokens from config - let getTestGenerationTokenLimit use its use-case default
      const providerConfig: AiProviderConfig = {
        provider: this.aiConfig.provider || 'anthropic',
        apiKey: this.aiConfig.apiKey || '',
        model: this.aiConfig.model || 'claude-3-sonnet'
        // Deliberately omitting maxTokens so TEST_GENERATION default (10000) is used
      };
      const maxTokens = getTestGenerationTokenLimit({}, providerConfig);
      const response = await client.complete(prompt, { maxTokens });

      // Log response details for debugging truncation
      logger.info(`AI response length: ${response.length} characters, maxTokens: ${maxTokens}`);
      if (response.length > 1000) {
        logger.debug('Response tail (last 200 chars):', response.substring(response.length - 200));
      }

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
    return `You are an expert security test engineer. Generate RED tests for a security vulnerability to prove it exists.

## Vulnerability Details:
- Type: ${vulnerability.type}
- Severity: ${vulnerability.severity}
- File: ${vulnerability.filePath || 'unknown'}
- Line: ${vulnerability.line}
- Description: ${vulnerability.description}
- Message: ${vulnerability.message}
${vulnerability.remediation ? `- Remediation: ${vulnerability.remediation}` : ''}

## Test Requirements (RFC-060):
1. Generate RED tests that prove the vulnerability exists:
   - Each test should FAIL on the current vulnerable code
   - Each test should PASS once the vulnerability is fixed
   - Tests must use ${options.testFramework || 'jest'} framework
   - Follow framework-specific best practices and idioms

2. Determine how many RED tests are needed based on the vulnerability:
   - Simple vulnerabilities: Generate 1 RED test
   - Complex vulnerabilities: Generate multiple RED tests (2-5 recommended, up to 10 max)
   - Examples of when multiple tests are needed:
     * Multi-vector attacks (e.g., SQL injection via multiple inputs)
     * Different exploit techniques for same vulnerability type
     * Edge cases that must all be addressed to fully fix the vulnerability

3. Use ${options.language || 'javascript'} language
4. Tests must be executable and use actual attack vectors
5. Include proper assertions to validate security

${fileContent ? `## Vulnerable Code:\n\`\`\`${options.language}\n${fileContent}\n\`\`\`` : ''}

## Response Format:
IMPORTANT: Return ONLY valid JSON. Keep test code CONCISE (max 10-15 lines per test).
Focus on the core vulnerability check, not elaborate setup.

For a single RED test, return:
{
  "red": {
    "testName": "short descriptive name",
    "testCode": "concise test code (10-15 lines max)",
    "attackVector": "malicious input",
    "expectedBehavior": "should_fail_on_vulnerable_code"
  }
}

For multiple RED tests (complex vulnerabilities), return:
{
  "redTests": [
    {
      "testName": "first attack vector name",
      "testCode": "test code",
      "attackVector": "first malicious input",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "second attack vector name",
      "testCode": "test code",
      "attackVector": "second malicious input",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
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

      // 3. Try to extract raw JSON object using proper nested-aware extraction
      if (!jsonString) {
        jsonString = this.extractJsonFromText(aiResponse);
      }

      // 4. If response looks like pure JSON, use it directly
      if (!jsonString && aiResponse.trim().startsWith('{')) {
        jsonString = aiResponse.trim();
      }

      if (!jsonString) {
        logger.error('No JSON found in AI response. Response preview:', aiResponse.substring(0, 200));
        return null;
      }

      // Log extracted JSON length for debugging
      logger.debug(`Extracted JSON string length: ${jsonString.length} characters`);

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

      // Only attempt JSON repair if it actually appears truncated
      // First try to parse as-is
      let isValidJson = false;
      try {
        JSON.parse(jsonString);
        isValidJson = true;
      } catch {
        // JSON is not valid, may need repair
      }

      // If the JSON appears truncated (ends mid-string), try to close it properly
      if (!isValidJson && this.isActuallyTruncatedString(jsonString)) {
        logger.warn('JSON appears truncated mid-string, attempting to close');

        // Count how many structures need closing
        const openSquareBrackets = (jsonString.match(/\[/g) || []).length;
        const closeSquareBrackets = (jsonString.match(/\]/g) || []).length;

        // Close the truncated string first
        jsonString += '"';

        // Close any open arrays
        if (openSquareBrackets > closeSquareBrackets) {
          jsonString += ']'.repeat(openSquareBrackets - closeSquareBrackets);
        }

        // Count open braces again after adding string close
        openBraces = (jsonString.match(/\{/g) || []).length;
        closeBraces = (jsonString.match(/\}/g) || []).length;

        // Close any remaining objects
        if (openBraces > closeBraces) {
          jsonString += '}'.repeat(openBraces - closeBraces);
        }
      }

      let parsed;
      try {
        parsed = JSON.parse(jsonString);
      } catch (parseError) {
        logger.error('Failed to parse JSON after cleanup attempts:', parseError);
        logger.debug('Attempted to parse:', jsonString.substring(0, 500));
        return null;
      }
      
      // RFC-060: Validate RED-only test suite structure
      // Accept either single RED test or array of RED tests
      if (!parsed.red && !parsed.redTests) {
        logger.error('Invalid test suite structure. No RED test(s) found. Keys:', Object.keys(parsed));
        return null;
      }

      // Log what we parsed
      if (parsed.redTests) {
        logger.info(`Successfully parsed ${parsed.redTests.length} RED tests for complex vulnerability`);
      } else if (parsed.red) {
        logger.info('Successfully parsed single RED test');
      }

      // Warn if GREEN/REFACTOR tests are present (should not be in VALIDATE phase)
      if (parsed.green || parsed.refactor) {
        logger.warn('Response contained GREEN/REFACTOR tests - stripping per RFC-060 (VALIDATE phase is RED-only)');
      }

      // Build RED-only result - either single or multiple
      const result: VulnerabilityTestSuite = {};

      if (parsed.redTests && Array.isArray(parsed.redTests)) {
        // Multiple RED tests for complex vulnerability
        result.redTests = parsed.redTests.map((test: any) => ({
          testName: test.testName || 'RED Test',
          testCode: test.testCode || '// Test code truncated',
          attackVector: test.attackVector || 'Unknown',
          expectedBehavior: 'should_fail_on_vulnerable_code' as const
        }));
      } else if (parsed.red) {
        // Single RED test
        result.red = {
          testName: parsed.red.testName || 'Vulnerability Test',
          testCode: parsed.red.testCode || '// Test code truncated',
          attackVector: parsed.red.attackVector || 'Unknown',
          expectedBehavior: 'should_fail_on_vulnerable_code' as const
        };
      }

      return result;
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

  /**
   * Detects if a JSON string is actually truncated (ends mid-string) vs just contains escaped quotes.
   * This is more accurate than the regex /\"[^\"]*$/ which doesn't handle escaped quotes.
   */
  private isActuallyTruncatedString(jsonString: string): boolean {
    // Simple heuristic: check if we're in an unterminated string by counting quote states
    let inString = false;
    let escape = false;

    for (let i = 0; i < jsonString.length; i++) {
      const char = jsonString[i];

      if (escape) {
        escape = false;
        continue;
      }

      if (char === '\\' && inString) {
        escape = true;
        continue;
      }

      if (char === '"') {
        inString = !inString;
      }
    }

    // If we end while in a string state, and the string doesn't end with "},
    // then it's likely actually truncated
    return inString && !jsonString.trim().endsWith('"}');
  }

  /**
   * Properly extracts JSON from text, handling nested objects correctly.
   * This replaces the buggy regex /\{[\s\S]*\}/ that truncates at the first closing brace.
   */
  private extractJsonFromText(text: string): string | null {
    // Find all potential JSON start/end positions
    const positions: Array<{start: number, end: number}> = [];
    let depth = 0;
    let inString = false;
    let escape = false;
    let jsonStart = -1;

    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      const prevChar = i > 0 ? text[i - 1] : '';

      // Handle escape sequences
      if (escape) {
        escape = false;
        continue;
      }

      if (char === '\\' && inString) {
        escape = true;
        continue;
      }

      // Handle strings (quotes not escaped)
      if (char === '"' && !escape) {
        // Check if this quote is inside a string value by looking for : before it
        // This is a simple heuristic but works for most JSON
        inString = !inString;
        continue;
      }

      // Only count braces outside of strings
      if (!inString) {
        if (char === '{') {
          if (depth === 0) {
            jsonStart = i;
          }
          depth++;
        } else if (char === '}') {
          depth--;
          if (depth === 0 && jsonStart !== -1) {
            positions.push({
              start: jsonStart,
              end: i + 1
            });
            jsonStart = -1;
          }
        }
      }
    }

    // Try to parse each potential JSON object, return the largest valid one
    let largestValid: string | null = null;
    let largestSize = 0;

    for (const pos of positions) {
      const candidate = text.substring(pos.start, pos.end);
      try {
        // Validate it's actual JSON
        JSON.parse(candidate);
        if (candidate.length > largestSize) {
          largestValid = candidate;
          largestSize = candidate.length;
        }
      } catch {
        // Invalid JSON, skip
      }
    }

    return largestValid;
  }
}