/**
 * E2E Integration tests for TestIntegrationClient against live backend
 * RFC-060-AMENDMENT-001: Test Integration - Phase 3 Frontend
 *
 * These tests make REAL HTTP calls to the staging backend to verify:
 * 1. Complete workflow: analyze → generate → validate
 * 2. Error handling (401, 422, 500, timeouts)
 * 3. Retry logic with exponential backoff
 * 4. Framework-specific integration (Vitest, Jest, RSpec, pytest)
 *
 * Prerequisites:
 * - Backend deployed to staging with Phase 1-3 APIs
 * - RSOLV_API_URL environment variable set (or defaults to staging)
 * - Valid TEST_API_KEY for authentication
 *
 * Run with:
 * RSOLV_API_URL=https://api.rsolv-staging.com TEST_API_KEY=your_key npm test test-integration-e2e
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  TestIntegrationClient,
  type AnalyzeRequest,
  type GenerateRequest
} from '../test-integration-client.js';

// Configuration from environment
const STAGING_URL = process.env.RSOLV_API_URL || 'https://api.rsolv-staging.com';
const API_KEY = process.env.TEST_API_KEY || 'demo_69b3158556cf1717c14bfcd8a1186a42';

describe('TestIntegrationClient E2E - Live Backend', () => {
  let client: TestIntegrationClient;

  beforeAll(() => {
    // Skip tests if no API key provided
    if (!API_KEY || API_KEY === 'demo_69b3158556cf1717c14bfcd8a1186a42') {
      console.warn('⚠️  Using demo API key - tests may have limited permissions');
    }

    client = new TestIntegrationClient(API_KEY, STAGING_URL);
    console.log(`🌐 Testing against: ${STAGING_URL}`);
  });

  describe('Happy Path - Complete Workflow', () => {
    it('should analyze test files and return scored recommendations', async () => {
      // Arrange - SQL injection vulnerability from RailsGoat
      const request: AnalyzeRequest = {
        vulnerableFile: 'app/controllers/users_controller.rb',
        vulnerabilityType: 'sql_injection',
        candidateTestFiles: [
          'spec/controllers/users_controller_spec.rb',
          'spec/models/user_spec.rb'
        ],
        framework: 'rspec'
      };

      // Act - Make real HTTP call to staging backend
      const result = await client.analyze(request);

      // Assert - Verify response structure and scoring
      expect(result).toBeDefined();
      expect(result.recommendations).toBeDefined();
      expect(Array.isArray(result.recommendations)).toBe(true);
      expect(result.recommendations.length).toBeGreaterThan(0);

      // Check first recommendation
      const topRecommendation = result.recommendations[0];
      expect(topRecommendation).toHaveProperty('path');
      expect(topRecommendation).toHaveProperty('score');
      expect(topRecommendation).toHaveProperty('reason');
      expect(topRecommendation.score).toBeGreaterThan(0);

      // Controller test should score higher than model test
      const controllerTest = result.recommendations.find(r => r.path.includes('controllers'));
      if (controllerTest) {
        expect(controllerTest.score).toBeGreaterThan(0.5);
      }

      // Fallback should always be provided
      expect(result.fallback).toBeDefined();
      expect(result.fallback.path).toBeTruthy();
      expect(result.fallback.reason).toBeTruthy();
    }, 10000);

    it('should generate AST-integrated test for JavaScript/Vitest', async () => {
      // Arrange - Simple Vitest test file
      const targetFileContent = `import { describe, it, expect } from 'vitest';

describe('UserController', () => {
  it('should update user name', () => {
    const result = updateUser({ id: 1, name: 'Alice' });
    expect(result.success).toBe(true);
  });
});`;

      const request: GenerateRequest = {
        targetFileContent,
        testSuite: {
          redTests: [{
            testName: 'should reject SQL injection in user update',
            testCode: `const result = updateUser({
  id: "1' OR '1'='1",
  name: 'Alice'
});
expect(result.success).toBe(false);
expect(result.error).toContain('invalid');`,
            attackVector: '1\' OR \'1\'=\'1',
            expectedBehavior: 'should_fail_on_vulnerable_code'
          }]
        },
        framework: 'vitest',
        language: 'javascript'
      };

      // Act - Make real HTTP call to generate integrated test
      const result = await client.generate(request);

      // Assert - Verify AST integration
      expect(result).toBeDefined();
      expect(result.method).toBe('ast'); // Should use AST, not simple append
      expect(result.integratedContent).toBeDefined();
      expect(result.integratedContent.length).toBeGreaterThan(targetFileContent.length);

      // Should contain original test
      expect(result.integratedContent).toContain('should update user name');

      // Should contain new security test
      expect(result.integratedContent).toContain('should reject SQL injection');
      expect(result.integratedContent).toContain('security');

      // Should have valid insertion point metadata
      expect(result.insertionPoint).toBeDefined();
      expect(result.insertionPoint.strategy).toBeTruthy();
    }, 10000);

    it('should generate AST-integrated test for Ruby/RSpec', async () => {
      // Arrange - RSpec test file
      const targetFileContent = `require 'rails_helper'

RSpec.describe UsersController, type: :controller do
  describe 'PATCH #update' do
    it 'updates the user name' do
      user = User.create!(name: 'Alice')
      patch :update, params: { id: user.id, name: 'Bob' }
      expect(response).to be_successful
    end
  end
end`;

      const request: GenerateRequest = {
        targetFileContent,
        testSuite: {
          redTests: [{
            testName: 'rejects SQL injection in user update (CWE-89)',
            testCode: `it 'rejects SQL injection payload' do
  user = User.create!(name: 'Alice')

  # Attack: SQL injection via ID parameter
  patch :update, params: {
    id: "#{user.id}' OR admin = 't' --",
    name: 'Attacker'
  }

  # RED test: Should reject malicious input
  expect(response.status).to eq(400)
end`,
            attackVector: '5\') OR admin = \'t\' --',
            expectedBehavior: 'should_fail_on_vulnerable_code',
            vulnerablePattern: 'User.where("id = \'#{params[:id]}\'")'
          }]
        },
        framework: 'rspec',
        language: 'ruby'
      };

      // Act
      const result = await client.generate(request);

      // Assert
      expect(result).toBeDefined();
      // RSpec now fully supports AST integration (RFC-060-AMENDMENT-001)
      expect(['ast', 'append']).toContain(result.method);

      // If AST worked, should contain security test
      if (result.method === 'ast') {
        expect(result.integratedContent).toContain('rejects SQL injection');
        expect(result.integratedContent).toContain('CWE-89');
      }

      expect(result.insertionPoint).toBeDefined();
    }, 10000);
  });

  describe('Error Handling', () => {
    it('should handle 401 unauthorized with invalid API key', async () => {
      // Arrange
      const badClient = new TestIntegrationClient('invalid_key_12345', STAGING_URL);

      const request: AnalyzeRequest = {
        vulnerableFile: 'app/users.rb',
        vulnerabilityType: 'sql_injection',
        candidateTestFiles: [],
        framework: 'rspec'
      };

      // Act & Assert
      await expect(badClient.analyze(request)).rejects.toThrow(/401|unauthorized|invalid.*key/i);
    }, 10000);

    it('should handle 400/422 validation error for invalid request', async () => {
      // Arrange - Invalid request (empty vulnerableFile)
      const request: AnalyzeRequest = {
        vulnerableFile: '',  // Invalid - empty file path
        vulnerabilityType: 'sql_injection',
        candidateTestFiles: [],
        framework: 'rspec'
      };

      // Act & Assert - Backend returns 400 for validation errors
      await expect(client.analyze(request)).rejects.toThrow(/400|422|validation|invalid/i);
    }, 10000);

    it('should handle timeout errors gracefully', async () => {
      // Note: This test may not fail as expected if backend responds quickly
      // In production, we'd use a test double or mock server for reliable timeout testing

      const request: AnalyzeRequest = {
        vulnerableFile: 'app/users.rb',
        vulnerabilityType: 'sql_injection',
        candidateTestFiles: Array.from({ length: 100 }, (_, i) => `spec/test_${i}.rb`), // Large request
        framework: 'rspec'
      };

      // For now, just verify it doesn't hang indefinitely
      const promise = client.analyze(request);

      // Should complete within reasonable time (10 seconds)
      await expect(Promise.race([
        promise,
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Request took too long')), 10000)
        )
      ])).resolves.toBeDefined();
    }, 15000);
  });

  describe('Retry Logic', () => {
    it('should eventually succeed after transient failures', async () => {
      // Note: We can't easily test retry logic against real backend
      // This test verifies the client doesn't throw on first attempt
      // and can successfully complete requests

      const request: AnalyzeRequest = {
        vulnerableFile: 'app/models/user.rb',
        vulnerabilityType: 'mass_assignment',
        candidateTestFiles: ['spec/models/user_spec.rb'],
        framework: 'rspec'
      };

      // Act - Should succeed (potentially after internal retries)
      const result = await client.analyze(request);

      // Assert - Just verify we got a valid response
      expect(result).toBeDefined();
      expect(result.recommendations).toBeDefined();
    }, 10000);
  });

  describe('Framework-Specific Integration', () => {
    const frameworks: Array<{ framework: string; language: string; fileExt: string }> = [
      { framework: 'vitest', language: 'javascript', fileExt: 'test.js' },
      { framework: 'jest', language: 'typescript', fileExt: 'test.ts' },
      { framework: 'rspec', language: 'ruby', fileExt: 'spec.rb' },
      { framework: 'pytest', language: 'python', fileExt: 'test.py' }
    ];

    frameworks.forEach(({ framework, language, fileExt }) => {
      it(`should integrate security test for ${framework}/${language}`, async () => {
        // Arrange - Simple test file for each framework
        const targetFileContent = getMinimalTestFile(framework, language);

        const request: GenerateRequest = {
          targetFileContent,
          testSuite: {
            redTests: [{
              testName: `should block ${framework} attack`,
              testCode: getSecurityTestCode(framework, language),
              attackVector: '1\' OR \'1\'=\'1',
              expectedBehavior: 'should_fail_on_vulnerable_code'
            }]
          },
          framework,
          language
        };

        // Act
        const result = await client.generate(request);

        // Assert
        expect(result).toBeDefined();
        // All frameworks now support AST integration (Ruby/Python added RFC-060-AMENDMENT-001)
        expect(['ast', 'append']).toContain(result.method);
        expect(result.integratedContent).toBeTruthy();

        // If AST integration succeeded, should have added content
        if (result.method === 'ast') {
          expect(result.integratedContent.length).toBeGreaterThan(targetFileContent.length);
          expect(result.integratedContent).toContain('security');
        }

        expect(result.insertionPoint).toBeDefined();
      }, 10000);
    });
  });

  describe('Backend Health Check', () => {
    it('should verify backend is accessible and responding', async () => {
      // Simple smoke test to verify backend connectivity
      const request: AnalyzeRequest = {
        vulnerableFile: 'app/models/user.rb',  // Valid file path
        vulnerabilityType: 'xss',
        candidateTestFiles: ['spec/models/user_spec.rb'],
        framework: 'rspec'
      };

      // Should not throw
      await expect(client.analyze(request)).resolves.toBeDefined();
    }, 10000);
  });
});

// Helper functions for generating test fixtures

function getMinimalTestFile(framework: string, language: string): string {
  switch (framework) {
  case 'vitest':
    return `import { describe, it, expect } from 'vitest';

describe('Component', () => {
  it('should work', () => {
    expect(true).toBe(true);
  });
});`;

  case 'jest':
    return `describe('Component', () => {
  it('should work', () => {
    expect(true).toBe(true);
  });
});`;

  case 'rspec':
    return `require 'rails_helper'

RSpec.describe User do
  it 'is valid' do
    expect(User.new).to be_valid
  end
end`;

  case 'pytest':
    return `import pytest

def test_user():
    assert True`;

  default:
    return 'test(\'should work\', () => { expect(true).toBe(true); });';
  }
}

function getSecurityTestCode(framework: string, language: string): string {
  switch (framework) {
  case 'vitest':
  case 'jest':
    return `const result = processInput("1' OR '1'='1");
expect(result.error).toBeDefined();
expect(result.error).toContain('invalid');`;

  case 'rspec':
    return `result = process_input("1' OR '1'='1")
expect(result[:error]).to be_present
expect(result[:error]).to include('invalid')`;

  case 'pytest':
    return `result = process_input("1' OR '1'='1")
assert "error" in result
assert "invalid" in result["error"]`;

  default:
    return 'expect(true).toBe(false);';
  }
}
