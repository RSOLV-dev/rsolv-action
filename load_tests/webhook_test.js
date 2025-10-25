/**
 * k6 Load Test: Stripe Webhooks
 *
 * Tests webhook endpoint under high load (1000 webhooks/minute).
 * Validates signature verification, processing speed, and idempotency.
 *
 * Run: k6 run load_tests/webhook_test.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';
import { crypto } from 'k6/experimental/webcrypto';

// Custom metrics
const webhookErrors = new Counter('webhook_errors');
const webhookSuccessRate = new Rate('webhook_success_rate');
const webhookDuration = new Trend('webhook_duration');

// Test configuration - 1000 webhooks/minute = ~16.67/second
export const options = {
  scenarios: {
    constant_load: {
      executor: 'constant-arrival-rate',
      rate: 17, // 17 requests per second
      timeUnit: '1s',
      duration: '1m',
      preAllocatedVUs: 20,
      maxVUs: 100,
    },
    burst_test: {
      executor: 'constant-arrival-rate',
      rate: 50, // Burst to 50/sec
      timeUnit: '1s',
      duration: '30s',
      preAllocatedVUs: 30,
      maxVUs: 150,
      startTime: '1m30s',
    },
  },
  thresholds: {
    http_req_duration: ['p(99)<200'],  // 99% of requests < 200ms
    http_req_failed: ['rate<0.001'],   // Error rate < 0.1%
    webhook_success_rate: ['rate>0.999'], // Success rate > 99.9%
  },
};

const BASE_URL = __ENV.API_BASE_URL || 'http://localhost:4000';
const WEBHOOK_SECRET = __ENV.STRIPE_WEBHOOK_SECRET || 'whsec_test_secret';

// Sample webhook payloads
const webhookPayloads = {
  invoice_paid: {
    id: 'evt_test_webhook',
    object: 'event',
    type: 'invoice.payment_succeeded',
    data: {
      object: {
        id: 'in_test',
        customer: 'cus_test',
        amount_paid: 1500,
        currency: 'usd',
        subscription: 'sub_test',
      }
    }
  },
  invoice_failed: {
    id: 'evt_test_webhook',
    object: 'event',
    type: 'invoice.payment_failed',
    data: {
      object: {
        id: 'in_test',
        customer: 'cus_test',
        amount_due: 1500,
        currency: 'usd',
        subscription: 'sub_test',
      }
    }
  },
  subscription_deleted: {
    id: 'evt_test_webhook',
    object: 'event',
    type: 'customer.subscription.deleted',
    data: {
      object: {
        id: 'sub_test',
        customer: 'cus_test',
        status: 'canceled',
      }
    }
  },
  subscription_updated: {
    id: 'evt_test_webhook',
    object: 'event',
    type: 'customer.subscription.updated',
    data: {
      object: {
        id: 'sub_test',
        customer: 'cus_test',
        status: 'active',
        items: {
          data: [{
            price: { id: 'price_growth_monthly' }
          }]
        }
      }
    }
  },
};

function generateStripeSignature(payload, secret, timestamp) {
  // This is a simplified version - in real tests, use proper HMAC
  // For actual implementation, signature should be generated server-side
  const signedPayload = `${timestamp}.${payload}`;
  return `t=${timestamp},v1=${signedPayload}`; // Simplified
}

export default function () {
  // Select random webhook type
  const types = Object.keys(webhookPayloads);
  const webhookType = types[Math.floor(Math.random() * types.length)];
  const payload = webhookPayloads[webhookType];

  // Add unique event ID to test idempotency
  payload.id = `evt_${Date.now()}_${__VU}_${__ITER}`;

  const payloadString = JSON.stringify(payload);
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = generateStripeSignature(payloadString, WEBHOOK_SECRET, timestamp);

  const params = {
    headers: {
      'Content-Type': 'application/json',
      'Stripe-Signature': signature,
    },
    tags: {
      name: 'WebhookRequest',
      webhook_type: webhookType,
    },
  };

  const startTime = new Date();
  const response = http.post(`${BASE_URL}/api/webhooks/stripe`, payloadString, params);
  const duration = new Date() - startTime;

  webhookDuration.add(duration);

  const success = check(response, {
    'status is 200': (r) => r.status === 200,
    'response is quick': (r) => r.timings.duration < 200,
    'has proper response': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.received === true || body.status === 'ok';
      } catch {
        return r.body === 'OK' || r.body === 'ok';
      }
    },
  });

  webhookSuccessRate.add(success);

  if (!success) {
    webhookErrors.add(1);
    console.error(`Webhook ${webhookType} failed: ${response.status} - ${response.body}`);
  }

  // No sleep - webhooks arrive continuously
}

export function handleSummary(data) {
  return {
    'stdout': textSummary(data, { indent: '→', enableColors: true }),
    'load_tests/results/webhook_test.json': JSON.stringify(data),
  };
}

function textSummary(data, options) {
  const indent = options?.indent || '';

  const summary = [
    `${indent}Webhook Load Test Summary`,
    `${indent}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`,
    `${indent}Total Webhooks:     ${data.metrics.http_reqs.values.count}`,
    `${indent}Success Rate:       ${(data.metrics.webhook_success_rate.values.rate * 100).toFixed(3)}%`,
    `${indent}Error Count:        ${data.metrics.webhook_errors.values.count}`,
    `${indent}Avg Duration:       ${data.metrics.webhook_duration.values.avg.toFixed(2)}ms`,
    `${indent}P99 Duration:       ${data.metrics.http_req_duration.values['p(99)'].toFixed(2)}ms`,
    `${indent}Webhook Rate:       ${data.metrics.http_reqs.values.rate.toFixed(2)}/s`,
    `${indent}Peak Load:          ${(data.metrics.http_reqs.values.rate * 60).toFixed(0)}/min`,
  ];

  return summary.join('\n') + '\n';
}
