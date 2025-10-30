/**
 * k6 Load Test: Customer Onboarding API
 *
 * Target: POST /api/v1/customers/onboard
 * Goal: 100 RPS for 5 minutes
 *
 * Tests:
 * - Ramp up to 100 RPS
 * - Sustain load for 5 minutes
 * - Verify rate limiting (10 req/min per IP)
 * - Monitor response times
 * - Track error rates
 *
 * Run: k6 run scripts/load-tests/onboarding-load-test.k6.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const onboardingDuration = new Trend('onboarding_duration');
const rateLimitCounter = new Counter('rate_limit_hits');
const successCounter = new Counter('successful_onboards');

// Test configuration
export const options = {
  stages: [
    { duration: '1m', target: 20 },   // Ramp up to 20 RPS
    { duration: '1m', target: 50 },   // Ramp up to 50 RPS
    { duration: '1m', target: 100 },  // Ramp up to 100 RPS
    { duration: '5m', target: 100 },  // Sustain 100 RPS for 5 minutes
    { duration: '1m', target: 0 },    // Ramp down
  ],
  thresholds: {
    'http_req_duration': ['p(95)<2000'], // 95% of requests should be below 2s
    'errors': ['rate<0.1'],              // Error rate should be below 10%
    'http_req_failed': ['rate<0.1'],     // Failed requests below 10%
  },
};

// Configuration
const BASE_URL = __ENV.API_URL || 'https://api.rsolv-staging.com';
const API_ENDPOINT = `${BASE_URL}/api/v1/customers/onboard`;

// Generate unique customer data
function generateCustomerData() {
  const timestamp = Date.now();
  const vuId = __VU; // Virtual User ID
  const iteration = __ITER; // Iteration number

  return {
    name: `Load Test Customer ${vuId}-${iteration}`,
    email: `loadtest-${vuId}-${iteration}-${timestamp}@example.com`,
    company: `Test Company ${vuId}`,
  };
}

export default function () {
  const customerData = generateCustomerData();

  const params = {
    headers: {
      'Content-Type': 'application/json',
    },
    tags: { name: 'CustomerOnboarding' },
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
    'load_tests/results/onboarding-results.json': JSON.stringify(data, null, 2),
    stdout: textSummary(data, { indent: ' ', enableColors: true }),
  };
}

function textSummary(data, options) {
  const indent = options?.indent || '';
  const enableColors = options?.enableColors || false;

  let output = '\n';
  output += `${indent}✓ Customer Onboarding Load Test Results\n`;
  output += `${indent}${'='.repeat(50)}\n\n`;

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
