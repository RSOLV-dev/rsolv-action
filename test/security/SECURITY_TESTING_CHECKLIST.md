# Security Testing Checklist

Comprehensive security validation for RSOLV billing integration.

## PCI Compliance

### Card Data Handling
- [ ] No card numbers in application logs
- [ ] No CVV codes in logs or database
- [ ] No cardholder names in logs
- [ ] Card data not stored in application database
- [ ] Only Stripe tokens/IDs stored
- [ ] Payment forms use Stripe Elements (client-side)
- [ ] No card data transmitted to backend
- [ ] Stripe API keys stored in environment variables only
- [ ] Production keys never committed to git

**Test Coverage:**
- `test/security/pci_compliance_test.exs` - Validates no card data in logs
- `test/security/data_storage_test.exs` - Ensures no PCI data persisted

### Encryption & Transport
- [ ] All payment pages served over HTTPS (production)
- [ ] TLS 1.2+ enforced for Stripe communication
- [ ] No downgrade to HTTP for payment flows
- [ ] Webhook endpoints validate Stripe signatures
- [ ] API keys transmitted over HTTPS only

**Test Coverage:**
- `test/security/tls_test.exs` - Validates TLS configuration
- `test/security/webhook_signature_test.exs` - Tests signature verification

## SQL Injection Prevention

### Parameterized Queries
- [ ] All Ecto queries use parameterized syntax
- [ ] No string concatenation in queries
- [ ] User input sanitized via Ecto changeset validations
- [ ] `Repo.query/3` uses `$1, $2` parameters (not string interpolation)
- [ ] Dynamic queries use `Ecto.Query.dynamic/2`

**Test Coverage:**
- `test/security/sql_injection_test.exs` - Attempts common SQL injection patterns

**Example Safe Query:**
```elixir
# SAFE - Parameterized
def get_customer(email) do
  from(c in Customer, where: c.email == ^email) |> Repo.one()
end

# UNSAFE - Don't do this
def get_customer_unsafe(email) do
  Repo.query("SELECT * FROM customers WHERE email = '#{email}'")
end
```

## Authentication & Authorization

### API Key Security
- [ ] API keys hashed before storage (bcrypt/argon2)
- [ ] API keys prefixed (rsolv_) for identification
- [ ] Rate limiting enforced (500 requests/hour)
- [ ] Invalid API keys return 401 (not 403)
- [ ] API key format validated before lookup
- [ ] Timing attack prevention (constant-time comparison)

**Test Coverage:**
- `test/security/api_key_test.exs` - API key validation and rate limiting
- `test/security/timing_attack_test.exs` - Constant-time comparison

### Session Management
- [ ] Session tokens use cryptographically secure random
- [ ] Sessions expire after inactivity
- [ ] Logout invalidates session tokens
- [ ] No session fixation vulnerabilities
- [ ] CSRF protection enabled (Phoenix default)

**Test Coverage:**
- `test/rsolv_web/controllers/auth_controller_test.exs` - Session handling

## Data Validation

### Input Sanitization
- [ ] Email addresses validated (format + deliverability)
- [ ] Passwords meet complexity requirements
- [ ] Plan names validated against allowed list
- [ ] Webhook payloads validated against schema
- [ ] User input HTML-escaped (Phoenix default)
- [ ] JSON inputs validated via schemas

**Test Coverage:**
- `test/rsolv/billing/customer_validation_test.exs` - Input validation
- `test/rsolv_web/schemas/billing_schema_test.exs` - Schema validation

### Injection Prevention
- [ ] No command injection (avoid `System.cmd` with user input)
- [ ] No path traversal (validate file paths)
- [ ] No LDAP injection (not applicable)
- [ ] No XML injection (not applicable)
- [ ] No template injection (use EEx safely)

**Test Coverage:**
- `test/security/injection_test.exs` - Various injection attack tests

## Webhook Security

### Stripe Webhook Validation
- [ ] Signature verification BEFORE processing
- [ ] Webhook secret stored securely (environment variable)
- [ ] Timestamp validation (prevent replay attacks)
- [ ] Event ID deduplication (idempotency)
- [ ] Webhook failures logged securely
- [ ] Rate limiting on webhook endpoint

**Test Coverage:**
- `test/security/webhook_signature_test.exs` - Signature validation
- `test/rsolv_web/controllers/webhook_controller_test.exs` - Webhook handling

**Example Implementation:**
```elixir
defmodule RsolvWeb.WebhookController do
  use RsolvWeb, :controller

  def stripe(conn, _params) do
    # REQUIRED: Verify signature FIRST
    with {:ok, event} <- verify_stripe_signature(conn),
         {:ok, _result} <- process_webhook(event) do
      send_resp(conn, 200, "OK")
    else
      {:error, :invalid_signature} ->
        send_resp(conn, 400, "Invalid signature")
      {:error, :replay_attack} ->
        send_resp(conn, 400, "Replayed event")
    end
  end
end
```

## Rate Limiting

### Endpoint Protection
- [ ] Global rate limit (per IP): 1000 requests/hour
- [ ] API rate limit (per key): 500 requests/hour
- [ ] Auth endpoints: 10 attempts/hour (brute force prevention)
- [ ] Webhook endpoint: 2000 webhooks/hour
- [ ] Rate limit headers returned (X-RateLimit-*)
- [ ] 429 status code with Retry-After header

**Test Coverage:**
- `test/security/rate_limiting_test.exs` - Rate limit enforcement
- `load_tests/api_rate_limit_test.js` - k6 load test

## Data Encryption

### At-Rest Encryption
- [ ] Database connection uses SSL/TLS
- [ ] Sensitive fields encrypted (if applicable)
- [ ] Encryption keys stored in secure vault
- [ ] No plaintext secrets in environment
- [ ] Stripe API keys rotated regularly

**Test Coverage:**
- `test/security/encryption_test.exs` - Validates encryption configuration

### In-Transit Encryption
- [ ] Production enforces HTTPS (force_ssl: true)
- [ ] API calls to Stripe use HTTPS
- [ ] WebSocket connections use WSS (if applicable)
- [ ] No mixed content warnings

**Test Coverage:**
- `test/security/tls_test.exs` - TLS enforcement

## Logging & Monitoring

### Secure Logging
- [ ] No passwords logged
- [ ] No API keys logged
- [ ] No card data logged (PCI requirement)
- [ ] Failed auth attempts logged
- [ ] Webhook failures logged (without sensitive data)
- [ ] Logs contain request IDs for tracing

**Test Coverage:**
- `test/security/logging_test.exs` - Validates log sanitization

### Audit Trail
- [ ] Subscription changes logged
- [ ] Payment events logged
- [ ] Customer data changes logged
- [ ] Admin actions logged
- [ ] Failed operations logged

**Test Coverage:**
- `test/rsolv/billing/audit_test.exs` - Audit trail completeness

## Error Handling

### Information Disclosure Prevention
- [ ] Production errors don't expose stack traces
- [ ] Database errors sanitized
- [ ] Generic error messages to users
- [ ] Detailed errors logged server-side only
- [ ] No sensitive data in error messages

**Test Coverage:**
- `test/security/error_disclosure_test.exs` - Error message sanitization

## Dependencies & Infrastructure

### Dependency Security
- [ ] Dependencies scanned for vulnerabilities (mix audit)
- [ ] Regular dependency updates
- [ ] Only trusted hex packages used
- [ ] Lock file committed (mix.lock)
- [ ] No deprecated packages

**CI Integration:**
```bash
mix hex.audit
mix deps.audit
```

### Infrastructure Security
- [ ] Postgres credentials rotated regularly
- [ ] Stripe API keys rotated regularly
- [ ] Environment variables not exposed in logs
- [ ] Kubernetes secrets used (not ConfigMaps)
- [ ] Network policies restrict traffic

**Test Coverage:**
- CI pipeline checks (automated via GitHub Actions)

## Compliance Checklist

### Before Production Deployment
- [ ] All security tests passing
- [ ] PCI compliance validated
- [ ] Penetration testing completed
- [ ] Security review approved
- [ ] Incident response plan documented
- [ ] Data breach notification process established

### Regular Audits (Monthly)
- [ ] Review access logs
- [ ] Check failed authentication attempts
- [ ] Validate rate limiting effectiveness
- [ ] Review Stripe security alerts
- [ ] Scan dependencies for vulnerabilities
- [ ] Rotate API keys and secrets

## Testing Commands

```bash
# Run all security tests
mix test test/security/

# Run with coverage
mix coveralls.html --umbrella --filter security

# Check dependencies
mix hex.audit

# Run Credo security checks
mix credo --strict --checks security

# Run load tests
k6 run load_tests/api_rate_limit_test.js

# Validate webhook signatures
mix test test/security/webhook_signature_test.exs
```

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PCI DSS Requirements](https://www.pcisecuritystandards.org/)
- [Stripe Security](https://stripe.com/docs/security)
- [Phoenix Security Best Practices](https://hexdocs.pm/phoenix/security.html)
