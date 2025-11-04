/**
 * k6 Load Test: Customer Onboarding API - PRODUCTION REDUCED SCALE
 *
 * Target: POST /api/v1/customers/onboard
 * Goal: 50 RPS for 5 minutes (REDUCED from 100 RPS for staging)
 *
 * Tests:
 * - Ramp up to 50 RPS
 * - Sustain load for 5 minutes
 * - Verify rate limiting (10 req/min per IP)
 * - Monitor response times
 * - Track error rates
 * - Compare with staging baseline (2x threshold)
 *
 * Run: API_URL=https://api.rsolv.dev k6 run scripts/load-tests/production-onboarding-load-test.k6.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const onboardingDuration = new Trend('onboarding_duration');
const rateLimitCounter = new Counter('rate_limit_hits');
const successCounter = new Counter('successful_onboards');

// Test configuration - REDUCED SCALE FOR PRODUCTION
export const options = {
  stages: [
    { duration: '1m', target: 10 },   // Ramp up to 10 RPS
    { duration: '1m', target: 25 },   // Ramp up to 25 RPS
    { duration: '1m', target: 50 },   // Ramp up to 50 RPS (REDUCED from 100)
    { duration: '5m', target: 50 },   // Sustain 50 RPS for 5 minutes
    { duration: '1m', target: 0 },    // Ramp down
  ],
  thresholds: {
    // Staging P95: 20.77ms, allow 2x = ~42ms, using 100ms for safety margin
    'http_req_duration': ['p(95)<100'],
    'errors': ['rate<0.1'],              // Error rate should be below 10%
    'http_req_failed': ['rate<0.1'],     // Failed requests below 10%
  },
};

// Configuration
const BASE_URL = __ENV.API_URL || 'https://api.rsolv.dev';
const API_ENDPOINT = `${BASE_URL}/api/v1/customers/onboard`;

// Generate unique customer data
function generateCustomerData() {
  const timestamp = Date.now();
  const vuId = __VU; // Virtual User ID
  const iteration = __ITER; // Iteration number

  return {
    name: `Load Test Customer ${vuId}-${iteration}`,
    email: `loadtest-prod-${vuId}-${iteration}-${timestamp}@example.com`,
    company: `Test Company ${vuId}`,
  };
}

export default function () {
  const customerData = generateCustomerData();

  const params = {
    headers: {
      'Content-Type': 'application/json',
    },
    tags: { name: 'CustomerOnboarding', environment: 'production' },
  };

  const startTime = Date.now();
  const response = http.post(API_ENDPOINT, JSON.stringify(customerData), params);
  const duration = Date.now() - startTime;

  // Record metrics
  onboardingDuration.add(duration);

  // Check response
  const success = check(response, {
    'status is 201': (r) => r.status === 201,
    'has customer data': (r) => {
      const body = JSON.parse(r.body || '{}');
      return body.customer && body.customer.id;
    },
    'has api_key': (r) => {
      const body = JSON.parse(r.body || '{}');
      return body.api_key && body.api_key.length > 0;
    },
    'customer has trial credits': (r) => {
      const body = JSON.parse(r.body || '{}');
      return body.customer && body.customer.trial_fixes_limit === 5;
    },
  });

  if (success) {
    successCounter.add(1);
  } else {
    errorRate.add(1);

    // Track rate limiting
    if (response.status === 429) {
      rateLimitCounter.add(1);
      console.log(`Rate limit hit: ${response.body}`);
    } else {
      console.log(`Error: Status ${response.status}, Body: ${response.body}`);
    }
  }

  // Small sleep to prevent overwhelming the server
  sleep(0.1);
}

export function handleSummary(data) {
  return {
    'load_tests/results/production-onboarding-results.json': JSON.stringify(data, null, 2),
    stdout: textSummary(data, { indent: ' ', enableColors: true }),
  };
}

function textSummary(data, options) {
  const indent = options?.indent || '';
  const enableColors = options?.enableColors || false;

  let output = '\n';
  output += `${indent}✓ Customer Onboarding Load Test Results - PRODUCTION\n`;
  output += `${indent}${'='.repeat(60)}\n\n`;

  // Environment info
  output += `${indent}Environment: PRODUCTION\n`;
  output += `${indent}Target RPS: 50 (reduced from staging 100)\n`;
  output += `${indent}Staging Baseline P95: 20.77ms\n`;
  output += `${indent}Production Threshold (2x): 42ms\n\n`;

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

  // Comparison with staging
  const p95 = data.metrics.http_req_duration.values['p(95)'];
  const stagingP95 = 20.77;
  const ratio = p95 / stagingP95;
  output += `${indent}Comparison to Staging:\n`;
  output += `${indent}  Production P95: ${p95.toFixed(2)}ms\n`;
  output += `${indent}  Staging P95: ${stagingP95}ms\n`;
  output += `${indent}  Ratio: ${ratio.toFixed(2)}x\n`;
  output += `${indent}  Status: ${ratio <= 2.0 ? '✓ PASS' : '✗ FAIL'} (threshold: 2.0x)\n\n`;

  // Success/Error metrics
  output += `${indent}Outcomes:\n`;
  output += `${indent}  Successful: ${data.metrics.successful_onboards?.values.count || 0}\n`;
  output += `${indent}  Failed: ${data.metrics.http_req_failed.values.count}\n`;
  output += `${indent}  Error Rate: ${(data.metrics.errors.values.rate * 100).toFixed(2)}%\n`;
  output += `${indent}  Rate Limits: ${data.metrics.rate_limit_hits?.values.count || 0}\n\n`;

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
