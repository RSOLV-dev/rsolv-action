/**
 * Test Integration Mock Handlers
 * Reusable handlers for test-integration endpoints across different environments
 */

import { http, HttpResponse } from 'msw';
import { createMockAnalyzeResponse, createMockGenerateResponse } from './helpers.js';

/**
 * Create test-integration handlers for a specific base URL
 */
export function createTestIntegrationHandlers(baseUrl: string) {
  return [
    // Analyze endpoint - scores test files for integration suitability
    http.post(`${baseUrl}/api/v1/test-integration/analyze`, async ({ request }) => {
      const body = await request.json() as Record<string, any>;
      return HttpResponse.json(createMockAnalyzeResponse(body));
    }),

    // Generate endpoint - generates AST-integrated test content
    http.post(`${baseUrl}/api/v1/test-integration/generate`, async ({ request }) => {
      const body = await request.json() as Record<string, any>;
      return HttpResponse.json(createMockGenerateResponse(body));
    })
  ];
}
