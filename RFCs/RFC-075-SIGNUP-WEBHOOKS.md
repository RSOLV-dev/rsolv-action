# RFC-075: Signup Webhook Events

**Status**: Draft (Future Work - post RFC-064)
**Created**: 2025-10-20
**Timeline**: TBD
**Dependencies**: RFC-065 (Automated Customer Provisioning)

## Related RFCs

**Depends on:**
- RFC-065 (Automated Customer Provisioning) - Provisioning events to publish

**Enables:**
- Third-party CRM integration
- Marketing automation triggers
- Custom analytics pipelines
- Zapier/Make/n8n integrations

## Summary

Publish webhook events when customers sign up, convert to paid, or complete key actions, enabling event-driven integrations with external tools.

## Problem

Current limitations:
- No way for external systems to react to RSOLV events
- Manual data sync to CRM/analytics
- No integration with marketing automation
- Limited extensibility

## Proposed Solution

### Webhook Events
```json
{
  "event": "customer.provisioned",
  "timestamp": "2025-10-20T12:34:56Z",
  "data": {
    "customer_id": "123",
    "email": "user@example.com",
    "subscription_plan": "trial"
  }
}
```

**Event Types:**
- `customer.provisioned` - New signup
- `customer.converted` - Trial → Paid
- `customer.scan_completed` - First scan done
- `customer.churned` - Cancelled subscription

### Delivery Mechanism
- HTTPS POST to customer-configured URLs
- Retry logic (exponential backoff)
- Signature verification (HMAC)
- Delivery status tracking

## Benefits

- **Flexible integrations** - Connect to any system
- **Event-driven architecture** - Real-time triggers
- **Ecosystem growth** - Enable third-party tools
- **Customer choice** - Use preferred CRM/analytics

## Technical Approach

**To be determined:**
- Webhook configuration UI (in customer portal)
- Event schema design (versioning strategy)
- Retry and failure handling
- Rate limiting and security

## Next Steps

1. Complete RFC-065 and RFC-071 (customer portal)
2. Research webhook best practices (Stripe, GitHub, etc.)
3. Design webhook management UI
4. Create detailed implementation plan
