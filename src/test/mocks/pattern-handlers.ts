/**
 * Pattern API Mock Handlers
 * Reusable handlers for pattern endpoints across different environments
 */

import { http, HttpResponse } from 'msw';
import { generateMockPatternsByLanguage } from './helpers.js';

/**
 * Create pattern GET handler for a specific base URL
 */
export function createPatternHandler(baseUrl: string) {
  return http.get(`${baseUrl}/api/v1/patterns`, ({ request }) => {
    const url = new URL(request.url);
    const language = url.searchParams.get('language') || 'javascript';
    const format = url.searchParams.get('format') || 'standard';

    const patterns = generateMockPatternsByLanguage(language);

    return HttpResponse.json({
      patterns,
      metadata: {
        count: patterns.length,
        language,
        format,
        access_level: 'full'
      }
    });
  });
}
