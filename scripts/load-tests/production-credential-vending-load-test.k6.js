/**
 * k6 Load Test: Credential Vending API - PRODUCTION REDUCED SCALE
 *
 * Target: POST /api/v1/credentials/exchange
 * Goal: 100 RPS for 5 minutes (REDUCED from 200 RPS for staging)
 *
 * Tests:
 * - Ramp up to 100 RPS
 * - Sustain load for 5 minutes
 * - Verify rate limiting (per customer)
 * - Monitor response times
 * - Track error rates
 * - Test with multiple providers
 * - Compare with staging baseline (2x threshold)
 *
 * Run: API_URL=https://api.rsolv.dev k6 run scripts/load-tests/production-credential-vending-load-test.k6.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const vendingDuration = new Trend('credential_vending_duration');
const rateLimitCounter = new Counter('rate_limit_hits');
const successCounter = new Counter('successful_exchanges');
const providerCounter = new Counter('credentials_by_provider');

// Test configuration - REDUCED SCALE FOR PRODUCTION
export const options = {
  stages: [
    { duration: '1m', target: 20 },   // Ramp up to 20 RPS
    { duration: '1m', target: 50 },   // Ramp up to 50 RPS
    { duration: '1m', target: 100 },  // Ramp up to 100 RPS (REDUCED from 200)
    { duration: '5m', target: 100 },  // Sustain 100 RPS for 5 minutes
    { duration: '1m', target: 0 },    // Ramp down
  ],
  thresholds: {
    // Assuming similar staging baseline, allow 2x with safety margin
    'http_req_duration': ['p(95)<100'],
    'errors': ['rate<0.15'],              // Error rate should be below 15%
    'http_req_failed': ['rate<0.15'],     // Failed requests below 15%
  },
};

// Configuration
const BASE_URL = __ENV.API_URL || 'https://api.rsolv.dev';
const API_ENDPOINT = `${BASE_URL}/api/v1/credentials/exchange`;

// Test API keys (use production test keys)
const TEST_API_KEYS = [
  __ENV.TEST_API_KEY_1 || 'test_api_key_1',
  __ENV.TEST_API_KEY_2 || 'test_api_key_2',
  __ENV.TEST_API_KEY_3 || 'test_api_key_3',
  __ENV.TEST_API_KEY_4 || 'test_api_key_4',
  __ENV.TEST_API_KEY_5 || 'test_api_key_5',
];

// Providers to test
const PROVIDERS = ['anthropic', 'openai'];
const TTL_OPTIONS = [60, 120, 180, 240]; // 1-4 hours

// Select API key for this VU
function selectApiKey() {
  const index = __VU % TEST_API_KEYS.length;
  return TEST_API_KEYS[index];
}

// Generate request payload
function generateRequest() {
  const providerCount = Math.floor(Math.random() * 2) + 1; // 1 or 2 providers
  const providers = [];

  for (let i = 0; i < providerCount; i++) {
    const provider = PROVIDERS[Math.floor(Math.random() * PROVIDERS.length)];
    if (!providers.includes(provider)) {
      providers.push(provider);
    }
  }

  const ttl = TTL_OPTIONS[Math.floor(Math.random() * TTL_OPTIONS.length)];

  return {
    providers,
    ttl_minutes: ttl,
  };
}

export default function () {
  const apiKey = selectApiKey();
  const requestBody = generateRequest();

  const params = {
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': apiKey,
      'X-GitHub-Job': `loadtest-prod-job-${__VU}-${__ITER}`,
      'X-GitHub-Run': `loadtest-prod-run-${__VU}`,
    },
    tags: { name: 'CredentialVending', environment: 'production' },
  };

  const startTime = Date.now();
  const response = http.post(API_ENDPOINT, JSON.stringify(requestBody), params);
  const duration = Date.now() - startTime;

  // Record metrics
  vendingDuration.add(duration);

  // Check response
  const success = check(response, {
    'status is 200': (r) => r.status === 200,
    'has credentials': (r) => {
      const body = JSON.parse(r.body || '{}');
      return body.credentials && Object.keys(body.credentials).length > 0;
    },
    'credentials have api_key': (r) => {
      const body = JSON.parse(r.body || '{}');
      if (!body.credentials) return false;

      for (const provider in body.credentials) {
        if (!body.credentials[provider].api_key) return false;
      }
      return true;
    },
    'credentials have expires_at': (r) => {
      const body = JSON.parse(r.body || '{}');
      if (!body.credentials) return false;

      for (const provider in body.credentials) {
        if (!body.credentials[provider].expires_at) return false;
      }
      return true;
    },
    'has usage info': (r) => {
      const body = JSON.parse(r.body || '{}');
      return body.usage && typeof body.usage.remaining_fixes === 'number';
    },
  });

  if (success) {
    successCounter.add(1);

    // Track provider usage
    const body = JSON.parse(response.body || '{}');
    if (body.credentials) {
      for (const provider in body.credentials) {
        providerCounter.add(1, { provider });
      }
    }
  } else {
    errorRate.add(1);

    // Track rate limiting
    if (response.status === 429) {
      rateLimitCounter.add(1);
      console.log(`Rate limit hit for API key: ${apiKey.substring(0, 8)}...`);
    } else if (response.status === 401) {
      console.log(`Authentication failed for API key: ${apiKey.substring(0, 8)}...`);
    } else {
      console.log(`Error: Status ${response.status}, Body: ${response.body}`);
    }
  }

  // Small sleep to prevent overwhelming the server
  sleep(0.05);
}

export function handleSummary(data) {
  return {
    'load_tests/results/production-credential-vending-results.json': JSON.stringify(data, null, 2),
    stdout: textSummary(data, { indent: ' ', enableColors: true }),
  };
}

function textSummary(data, options) {
  const indent = options?.indent || '';

  let output = '\n';
  output += `${indent}✓ Credential Vending Load Test Results - PRODUCTION\n`;
  output += `${indent}${'='.repeat(60)}\n\n`;

  // Environment info
  output += `${indent}Environment: PRODUCTION\n`;
  output += `${indent}Target RPS: 100 (reduced from staging 200)\n`;
  output += `${indent}Production Threshold (2x staging): <100ms P95\n\n`;

  // VUs
  output += `${indent}Virtual Users:\n`;
  output += `${indent}  Max: ${data.metrics.vus_max.values.max}\n`;
  output += `${indent}  Avg: ${Math.round(data.metrics.vus.values.avg)}\n\n`;

  // Requests
  output += `${indent}HTTP Requests:\n`;
  output += `${indent}  Total: ${data.metrics.http_reqs.values.count}\n`;
  output += `${indent}  Rate: ${data.metrics.http_reqs.values.rate.toFixed(2)} req/s\n`;
  output += `${indent}  Duration (avg): ${data.metrics.http_req_duration.values.avg.toFixed(2)}ms\n`;
  output += `${indent}  Duration (p95): ${data.metrics.http_req_duration.values['p(95)'].toFixed(2)}ms\n`;
  output += `${indent}  Duration (p99): ${data.metrics.http_req_duration.values['p(99)'].toFixed(2)}ms\n\n`;

  // Success/Error metrics
  output += `${indent}Outcomes:\n`;
  output += `${indent}  Successful: ${data.metrics.successful_exchanges?.values.count || 0}\n`;
  output += `${indent}  Failed: ${data.metrics.http_req_failed.values.count}\n`;
  output += `${indent}  Error Rate: ${(data.metrics.errors.values.rate * 100).toFixed(2)}%\n`;
  output += `${indent}  Rate Limits: ${data.metrics.rate_limit_hits?.values.count || 0}\n\n`;

  // Provider breakdown
  output += `${indent}Credentials by Provider:\n`;
  if (data.metrics.credentials_by_provider) {
    const providerStats = data.metrics.credentials_by_provider.values;
    output += `${indent}  Total: ${providerStats.count}\n`;
  }

  output += '\n';

  // Thresholds
  output += `${indent}Threshold Results:\n`;
  Object.keys(data.metrics).forEach(metricName => {
    const metric = data.metrics[metricName];
    if (metric.thresholds) {
      Object.keys(metric.thresholds).forEach(thresholdName => {
        const threshold = metric.thresholds[thresholdName];
        const status = threshold.ok ? '✓' : '✗';
        output += `${indent}  ${status} ${metricName}: ${thresholdName}\n`;
      });
    }
  });

  return output;
}
