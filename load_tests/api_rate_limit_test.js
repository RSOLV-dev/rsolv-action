/**
 * k6 Load Test: API Rate Limiting
 *
 * Tests API rate limits (500 requests/hour per API key).
 * Validates rate limiting enforcement, error responses, and retry-after headers.
 *
 * Run: k6 run load_tests/api_rate_limit_test.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate } from 'k6/metrics';

// Custom metrics
const rateLimitHits = new Counter('rate_limit_hits');
const successBeforeLimit = new Counter('success_before_limit');
const rateLimitCorrect = new Rate('rate_limit_enforced_correctly');

// Test configuration
export const options = {
  scenarios: {
    rate_limit_test: {
      executor: 'per-vu-iterations',
      vus: 1, // Single user to test rate limit
      iterations: 550, // Attempt 550 requests (should fail after 500)
      maxDuration: '2h',
    },
  },
  thresholds: {
    rate_limit_enforced_correctly: ['rate>0.99'], // Rate limit must work
  },
};

const BASE_URL = __ENV.API_BASE_URL || 'http://localhost:4000';
const API_KEY = __ENV.API_KEY || 'rsolv_test_key_123';

let requestCount = 0;
let rateLimitTriggered = false;

export default function () {
  requestCount++;

  const params = {
    headers: {
      'X-API-Key': API_KEY,
      'Content-Type': 'application/json',
    },
    tags: {
      name: 'RateLimitTest',
      request_number: requestCount,
    },
  };

  const response = http.get(`${BASE_URL}/api/health`, params);

  if (!rateLimitTriggered) {
    // Before hitting rate limit
    if (response.status === 200) {
      successBeforeLimit.add(1);

      // Check rate limit headers
      const remaining = parseInt(response.headers['X-RateLimit-Remaining'] || '999');
      const limit = parseInt(response.headers['X-RateLimit-Limit'] || '500');

      check(response, {
        'has rate limit headers': (r) => r.headers['X-RateLimit-Limit'] !== undefined,
        'limit is 500': (r) => parseInt(r.headers['X-RateLimit-Limit']) === 500,
        'remaining decreases': (r) => {
          const rem = parseInt(r.headers['X-RateLimit-Remaining']);
          return rem < limit;
        },
      });

      console.log(`Request ${requestCount}: ${response.status} (${remaining}/${limit} remaining)`);

    } else if (response.status === 429) {
      // Rate limit triggered
      rateLimitTriggered = true;
      rateLimitHits.add(1);

      const success = check(response, {
        'status is 429': (r) => r.status === 429,
        'has retry-after header': (r) => r.headers['Retry-After'] !== undefined,
        'has rate limit headers': (r) => r.headers['X-RateLimit-Limit'] !== undefined,
        'remaining is 0': (r) => parseInt(r.headers['X-RateLimit-Remaining']) === 0,
        'error message present': (r) => {
          try {
            const body = JSON.parse(r.body);
            return body.error !== undefined || body.message !== undefined;
          } catch {
            return false;
          }
        },
      });

      rateLimitCorrect.add(success);

      const retryAfter = response.headers['Retry-After'];
      const remaining = response.headers['X-RateLimit-Remaining'];

      console.log(`🚫 Rate limit triggered at request ${requestCount}`);
      console.log(`   Retry-After: ${retryAfter}s`);
      console.log(`   Remaining: ${remaining}`);
      console.log(`   Expected trigger: ~500 requests`);

      // Verify we're close to 500 requests
      const withinExpectedRange = requestCount >= 490 && requestCount <= 510;
      rateLimitCorrect.add(withinExpectedRange);

      if (!withinExpectedRange) {
        console.error(`⚠️  Rate limit triggered at ${requestCount}, expected ~500`);
      }
    }
  } else {
    // After rate limit triggered - all should be 429
    const stillLimited = check(response, {
      'still rate limited': (r) => r.status === 429,
    });

    rateLimitCorrect.add(stillLimited);

    if (response.status !== 429) {
      console.error(`⚠️  Expected 429 but got ${response.status} after rate limit`);
    }
  }

  // Small delay between requests to not overwhelm server
  sleep(0.01); // 10ms between requests = ~100 req/s
}

export function handleSummary(data) {
  const totalRequests = data.metrics.http_reqs.values.count;
  const successCount = data.metrics.success_before_limit.values.count;
  const rateLimitCount = data.metrics.rate_limit_hits.values.count;

  const summary = [
    '',
    '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
    'API Rate Limit Test Results',
    '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
    `Total Requests:           ${totalRequests}`,
    `Successful (before limit):${successCount}`,
    `Rate Limited (429):       ${rateLimitCount}`,
    `Rate Limit Triggered At:  Request ~${successCount}`,
    `Expected Trigger:         ~500 requests`,
    `Variance:                 ${Math.abs(successCount - 500)} requests`,
    '',
    successCount >= 490 && successCount <= 510
      ? '✅ Rate limit enforcement is correct (within ±10 requests)'
      : '❌ Rate limit enforcement outside expected range',
    '',
    rateLimitCount > 0
      ? '✅ Rate limit properly returns 429 status'
      : '❌ Rate limit not triggered',
    '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
    '',
  ];

  return {
    'stdout': summary.join('\n'),
    'load_tests/results/api_rate_limit_test.json': JSON.stringify(data),
  };
}
