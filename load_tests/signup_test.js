/**
 * k6 Load Test: User Signup
 *
 * Tests signup endpoint under load with 100 concurrent users.
 * Validates response times, error rates, and system stability.
 *
 * Run: k6 run load_tests/signup_test.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// Custom metrics
const signupErrors = new Counter('signup_errors');
const signupSuccessRate = new Rate('signup_success_rate');
const signupDuration = new Trend('signup_duration');

// Test configuration
export const options = {
  stages: [
    { duration: '30s', target: 20 },  // Ramp up to 20 users
    { duration: '1m', target: 50 },   // Ramp up to 50 users
    { duration: '2m', target: 100 },  // Ramp up to 100 users
    { duration: '2m', target: 100 },  // Stay at 100 users
    { duration: '30s', target: 0 },   // Ramp down to 0
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'],  // 95% of requests < 500ms
    http_req_failed: ['rate<0.01'],    // Error rate < 1%
    signup_success_rate: ['rate>0.95'], // Success rate > 95%
  },
};

const BASE_URL = __ENV.API_BASE_URL || 'http://localhost:4000';

export default function () {
  const uniqueEmail = `loadtest-${Date.now()}-${__VU}-${__ITER}@example.com`;

  const payload = JSON.stringify({
    email: uniqueEmail,
    password: 'LoadTest123!@#',
    password_confirmation: 'LoadTest123!@#',
    plan: 'growth',
    payment_method: 'pm_card_visa', // Stripe test token
  });

  const params = {
    headers: {
      'Content-Type': 'application/json',
    },
    tags: { name: 'SignupRequest' },
  };

  const startTime = new Date();
  const response = http.post(`${BASE_URL}/api/auth/signup`, payload, params);
  const duration = new Date() - startTime;

  // Record metrics
  signupDuration.add(duration);

  // Check response
  const success = check(response, {
    'status is 201': (r) => r.status === 201,
    'has customer_id': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.customer_id !== undefined;
      } catch {
        return false;
      }
    },
    'has subscription': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.subscription !== undefined;
      } catch {
        return false;
      }
    },
  });

  signupSuccessRate.add(success);

  if (!success) {
    signupErrors.add(1);
    console.error(`Signup failed for ${uniqueEmail}: ${response.status} - ${response.body}`);
  }

  // Random think time between requests
  sleep(Math.random() * 3 + 1); // 1-4 seconds
}

export function handleSummary(data) {
  return {
    'stdout': textSummary(data, { indent: '→', enableColors: true }),
    'load_tests/results/signup_test.json': JSON.stringify(data),
  };
}

function textSummary(data, options) {
  const indent = options?.indent || '';
  const enableColors = options?.enableColors || false;

  const summary = [
    `${indent}Signup Load Test Summary`,
    `${indent}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`,
    `${indent}Total Requests:     ${data.metrics.http_reqs.values.count}`,
    `${indent}Success Rate:       ${(data.metrics.signup_success_rate.values.rate * 100).toFixed(2)}%`,
    `${indent}Error Count:        ${data.metrics.signup_errors.values.count}`,
    `${indent}Avg Duration:       ${data.metrics.signup_duration.values.avg.toFixed(2)}ms`,
    `${indent}P95 Duration:       ${data.metrics.http_req_duration.values['p(95)'].toFixed(2)}ms`,
    `${indent}Request Rate:       ${data.metrics.http_reqs.values.rate.toFixed(2)}/s`,
  ];

  return summary.join('\n') + '\n';
}
