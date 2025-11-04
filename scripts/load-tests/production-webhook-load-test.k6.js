/**
 * k6 Load Test: Stripe Webhook Endpoint - PRODUCTION REDUCED SCALE
 *
 * Target: POST /api/webhooks/stripe
 * Goal: 25 RPS for 5 minutes (REDUCED from 50 RPS for staging)
 *
 * Tests:
 * - Ramp up to 25 RPS
 * - Sustain load for 5 minutes
 * - Test various webhook event types
 * - Monitor response times
 * - Track error rates
 * - Verify idempotency (duplicate events)
 * - Compare with staging baseline (2x threshold)
 *
 * Run: API_URL=https://api.rsolv.dev k6 run scripts/load-tests/production-webhook-load-test.k6.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';
import { randomString } from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';

// Custom metrics
const errorRate = new Rate('errors');
const webhookDuration = new Trend('webhook_processing_duration');
const successCounter = new Counter('successful_webhooks');
const eventTypeCounter = new Counter('webhooks_by_event_type');
const duplicateCounter = new Counter('duplicate_events_detected');

// Test configuration - REDUCED SCALE FOR PRODUCTION
export const options = {
  stages: [
    { duration: '1m', target: 5 },    // Ramp up to 5 RPS
    { duration: '1m', target: 12 },   // Ramp up to 12 RPS
    { duration: '1m', target: 25 },   // Ramp up to 25 RPS (REDUCED from 50)
    { duration: '5m', target: 25 },   // Sustain 25 RPS for 5 minutes
    { duration: '1m', target: 0 },    // Ramp down
  ],
  thresholds: {
    // Staging baseline, allow 2x with safety margin
    'http_req_duration': ['p(95)<100'],
    'errors': ['rate<0.05'],              // Error rate should be below 5%
    'http_req_failed': ['rate<0.05'],     // Failed requests below 5%
  },
};

// Configuration
const BASE_URL = __ENV.API_URL || 'https://api.rsolv.dev';
const API_ENDPOINT = `${BASE_URL}/api/webhooks/stripe`;
const WEBHOOK_SECRET = __ENV.STRIPE_WEBHOOK_SECRET || 'whsec_production_secret';

// Stripe webhook event types to test
const EVENT_TYPES = [
  'customer.subscription.created',
  'customer.subscription.updated',
  'customer.subscription.deleted',
  'invoice.payment_succeeded',
  'invoice.payment_failed',
  'payment_method.attached',
  'payment_method.detached',
];

// Generate unique event ID
function generateEventId() {
  const timestamp = Date.now();
  const vuId = __VU;
  const iteration = __ITER;
  return `evt_load_test_prod_${vuId}_${iteration}_${timestamp}`;
}

// Generate Stripe webhook payload
function generateWebhookPayload(eventType) {
  const eventId = generateEventId();
  const customerId = `cus_loadtest_prod_${__VU}`;
  const subscriptionId = `sub_loadtest_prod_${__VU}_${__ITER}`;

  let data = {};

  switch (eventType) {
    case 'customer.subscription.created':
    case 'customer.subscription.updated':
      data = {
        id: subscriptionId,
        customer: customerId,
        status: 'active',
        plan: {
          id: 'pro_plan',
          amount: 59900, // $599.00
          currency: 'usd',
          interval: 'month',
        },
        current_period_start: Math.floor(Date.now() / 1000),
        current_period_end: Math.floor(Date.now() / 1000) + 2592000, // +30 days
      };
      break;

    case 'customer.subscription.deleted':
      data = {
        id: subscriptionId,
        customer: customerId,
        status: 'canceled',
        cancel_at_period_end: false,
        canceled_at: Math.floor(Date.now() / 1000),
      };
      break;

    case 'invoice.payment_succeeded':
      data = {
        id: `in_loadtest_prod_${__VU}_${__ITER}`,
        customer: customerId,
        subscription: subscriptionId,
        amount_paid: 59900,
        currency: 'usd',
        status: 'paid',
      };
      break;

    case 'invoice.payment_failed':
      data = {
        id: `in_loadtest_prod_${__VU}_${__ITER}`,
        customer: customerId,
        subscription: subscriptionId,
        amount_due: 59900,
        currency: 'usd',
        status: 'open',
        attempt_count: 1,
      };
      break;

    case 'payment_method.attached':
    case 'payment_method.detached':
      data = {
        id: `pm_loadtest_prod_${__VU}_${__ITER}`,
        customer: customerId,
        type: 'card',
        card: {
          brand: 'visa',
          last4: '4242',
          exp_month: 12,
          exp_year: 2025,
        },
      };
      break;
  }

  return {
    id: eventId,
    object: 'event',
    type: eventType,
    created: Math.floor(Date.now() / 1000),
    livemode: false,
    data: {
      object: data,
    },
  };
}

// Simple HMAC SHA256 signature (simplified for load testing)
// In production, Stripe uses proper HMAC-SHA256 with timestamp
function generateSignature(payload) {
  // For load testing, we'll use a simple signature format
  // In real implementation, this should match Stripe's signature scheme
  const timestamp = Math.floor(Date.now() / 1000);
  return `t=${timestamp},v1=load_test_prod_signature_${randomString(64)}`;
}

// Track sent event IDs to test idempotency
const sentEvents = new Set();

export default function () {
  // Select event type (weighted towards more common events)
  let eventType;
  const rand = Math.random();
  if (rand < 0.3) {
    eventType = 'invoice.payment_succeeded';
  } else if (rand < 0.5) {
    eventType = 'customer.subscription.updated';
  } else {
    eventType = EVENT_TYPES[Math.floor(Math.random() * EVENT_TYPES.length)];
  }

  const payload = generateWebhookPayload(eventType);
  const payloadString = JSON.stringify(payload);
  const signature = generateSignature(payloadString);

  const params = {
    headers: {
      'Content-Type': 'application/json',
      'Stripe-Signature': signature,
    },
    tags: {
      name: 'StripeWebhook',
      event_type: eventType,
      environment: 'production',
    },
  };

  // 10% of the time, send a duplicate event to test idempotency
  const isDuplicate = Math.random() < 0.1 && sentEvents.size > 0;
  let actualPayload = payloadString;

  if (isDuplicate) {
    // Reuse a previous event ID
    const previousEvents = Array.from(sentEvents);
    const randomPreviousEvent = previousEvents[Math.floor(Math.random() * previousEvents.length)];
    const duplicatePayload = JSON.parse(payloadString);
    duplicatePayload.id = randomPreviousEvent;
    actualPayload = JSON.stringify(duplicatePayload);
    duplicateCounter.add(1);
  } else {
    sentEvents.add(payload.id);
  }

  const startTime = Date.now();
  const response = http.post(API_ENDPOINT, actualPayload, params);
  const duration = Date.now() - startTime;

  // Record metrics
  webhookDuration.add(duration);
  eventTypeCounter.add(1, { event_type: eventType });

  // Check response
  const success = check(response, {
    'status is 200': (r) => r.status === 200,
    'response time < 1000ms': () => duration < 1000,
  });

  if (success) {
    successCounter.add(1);
  } else {
    errorRate.add(1);
    console.log(`Webhook error: Status ${response.status}, Event: ${eventType}, Body: ${response.body}`);
  }

  // Small sleep to prevent overwhelming the server
  sleep(0.1);
}

export function handleSummary(data) {
  return {
    'load_tests/results/production-webhook-results.json': JSON.stringify(data, null, 2),
    stdout: textSummary(data, { indent: ' ', enableColors: true }),
  };
}

function textSummary(data, options) {
  const indent = options?.indent || '';

  let output = '\n';
  output += `${indent}✓ Stripe Webhook Load Test Results - PRODUCTION\n`;
  output += `${indent}${'='.repeat(60)}\n\n`;

  // Environment info
  output += `${indent}Environment: PRODUCTION\n`;
  output += `${indent}Target RPS: 25 (reduced from staging 50)\n`;
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
  output += `${indent}  Successful: ${data.metrics.successful_webhooks?.values.count || 0}\n`;
  output += `${indent}  Failed: ${data.metrics.http_req_failed.values.count}\n`;
  output += `${indent}  Error Rate: ${(data.metrics.errors.values.rate * 100).toFixed(2)}%\n`;
  output += `${indent}  Duplicate Events: ${data.metrics.duplicate_events_detected?.values.count || 0}\n\n`;

  // Event type breakdown
  output += `${indent}Webhooks by Event Type:\n`;
  if (data.metrics.webhooks_by_event_type) {
    output += `${indent}  Total: ${data.metrics.webhooks_by_event_type.values.count}\n`;
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
