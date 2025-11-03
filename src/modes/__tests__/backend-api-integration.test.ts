/**
 * E2E Test for Staging Backend Integration
 * RFC-060-AMENDMENT-001: Real API calls to staging environment
 *
 * This test makes REAL API calls to https://api.rsolv-staging.com
 * No mocks - tests actual backend integration end-to-end
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { TestIntegrationClient } from '../test-integration-client.js';

describe('E2E - Staging Backend Integration', () => {
  let client: TestIntegrationClient;

  beforeAll(() => {
    const apiUrl = process.env.RSOLV_API_URL || 'https://api.rsolv-staging.com';
    const apiKey = process.env.RSOLV_API_KEY || 'master_58d4c71fcbf98327b088b21dd24f6c4327e87b4f4e080f7f81ebbc2f0e0aef32';

    client = new TestIntegrationClient(apiKey, apiUrl);

    console.log(`[E2E] Testing against: ${apiUrl}`);
    console.log(`[E2E] Using API key: ${apiKey.slice(0, 20)}...`);
  });

  it('should analyze Ruby test files and return recommendations', async () => {
    const response = await client.analyze({
      vulnerableFile: 'app/controllers/users_controller.rb',
      vulnerabilityType: 'SQL injection',
      candidateTestFiles: [
        'spec/controllers/users_controller_spec.rb',
        'spec/models/user_spec.rb'
      ],
      framework: 'rspec'
    });

    expect(response).toBeDefined();
    expect(response.recommendations).toBeDefined();
    expect(Array.isArray(response.recommendations)).toBe(true);
    expect(response.recommendations.length).toBeGreaterThan(0);

    const topRecommendation = response.recommendations[0];
    expect(topRecommendation.path).toBeDefined();
    expect(topRecommendation.score).toBeGreaterThan(0);
    expect(topRecommendation.reason).toBeDefined();

    console.log(`[E2E] Recommended file: ${topRecommendation.path} (score: ${topRecommendation.score})`);
  }, 15000);

  it('should generate AST-integrated Ruby test content', async () => {
    const targetFileContent = `describe UsersController do
  before do
    @user = User.create(name: 'test')
  end

  it 'creates user' do
    expect(User.count).to eq(1)
  end
end`;

    const response = await client.generate({
      targetFileContent,
      testSuite: {
        redTests: [{
          testName: 'rejects SQL injection',
          testCode: `post :search, params: { q: "admin'; DROP TABLE users;--" }\nexpect(response.status).to eq(400)`,
          attackVector: "admin'; DROP TABLE users;--"
        }]
      },
      framework: 'rspec',
      language: 'ruby'
    });

    expect(response).toBeDefined();
    expect(response.integratedContent).toBeDefined();
    expect(response.method).toBe('ast');
    expect(response.insertionPoint).toBeDefined();
    expect(response.insertionPoint.line).toBeGreaterThan(0);

    // Verify the integrated content includes the security test
    expect(response.integratedContent).toContain('rejects SQL injection');
    expect(response.integratedContent).toContain("admin'; DROP TABLE users;--");

    console.log(`[E2E] Generated ${response.integratedContent.split('\n').length} lines using ${response.method} method`);
    console.log(`[E2E] Insertion point: line ${response.insertionPoint.line} (${response.insertionPoint.strategy})`);
  }, 15000);

  it('should analyze JavaScript test files and return recommendations', async () => {
    const response = await client.analyze({
      vulnerableFile: 'src/controllers/users.ts',
      vulnerabilityType: 'XSS vulnerability',
      candidateTestFiles: [
        'test/controllers/users.test.ts',
        '__tests__/users.test.ts'
      ],
      framework: 'vitest'
    });

    expect(response).toBeDefined();
    expect(response.recommendations).toBeDefined();
    expect(response.recommendations.length).toBeGreaterThan(0);

    const topRecommendation = response.recommendations[0];
    console.log(`[E2E] JavaScript recommended: ${topRecommendation.path} (score: ${topRecommendation.score})`);
  }, 15000);

  it('should generate AST-integrated JavaScript test content', async () => {
    const targetFileContent = `import { describe, it, expect } from 'vitest';
import { createUser } from '../src/controllers/users.js';

describe('UsersController', () => {
  it('creates user', () => {
    const user = createUser({ name: 'test' });
    expect(user.name).toBe('test');
  });
});`;

    const response = await client.generate({
      targetFileContent,
      testSuite: {
        redTests: [{
          testName: 'prevents XSS in user input',
          testCode: `const maliciousInput = '<script>alert(\"xss\")</script>';\nconst result = createUser({ name: maliciousInput });\nexpect(result.name).not.toContain('<script>');`,
          attackVector: '<script>alert("xss")</script>'
        }]
      },
      framework: 'vitest',
      language: 'javascript'
    });

    expect(response).toBeDefined();
    expect(response.integratedContent).toBeDefined();
    expect(response.method).toBe('ast');
    expect(response.integratedContent).toContain('prevents XSS in user input');

    console.log(`[E2E] JavaScript generated ${response.integratedContent.split('\n').length} lines`);
  }, 15000);

  it('should analyze Python test files and return recommendations', async () => {
    const response = await client.analyze({
      vulnerableFile: 'app/views.py',
      vulnerabilityType: 'SQL injection',
      candidateTestFiles: [
        'tests/test_views.py',
        'test/test_app.py'
      ],
      framework: 'pytest'
    });

    expect(response).toBeDefined();
    expect(response.recommendations).toBeDefined();
    expect(response.recommendations.length).toBeGreaterThan(0);

    const topRecommendation = response.recommendations[0];
    console.log(`[E2E] Python recommended: ${topRecommendation.path} (score: ${topRecommendation.score})`);
  }, 15000);

  it('should generate AST-integrated Python test content', async () => {
    const targetFileContent = `def test_create_user():
    user = create_user(name="test")
    assert user.name == "test"`;

    const response = await client.generate({
      targetFileContent,
      testSuite: {
        redTests: [{
          testName: 'test_sql_injection_prevented',
          testCode: `malicious_input = "'; DROP TABLE users;--"\nresult = search_users(malicious_input)\nassert result.status_code == 400`,
          attackVector: "'; DROP TABLE users;--"
        }]
      },
      framework: 'pytest',
      language: 'python'
    });

    expect(response).toBeDefined();
    expect(response.integratedContent).toBeDefined();
    expect(response.method).toBe('ast');
    expect(response.integratedContent).toContain('test_sql_injection_prevented');

    console.log(`[E2E] Python generated ${response.integratedContent.split('\n').length} lines`);
  }, 15000);
});
