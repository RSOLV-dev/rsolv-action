# Testing Documentation

This directory contains testing guides and results for the RSOLV platform.

## Webhook Testing

### WEBHOOK_CANCELLATION_TEST.md
Comprehensive guide for testing subscription cancellation webhooks. Includes:
- Manual testing steps
- IEx commands for interactive testing
- Edge cases to test
- Expected behavior verification
- Troubleshooting guide

### WEBHOOK_TEST_RESULTS.md
Results from automated test execution on 2025-11-06. Documents:
- Test execution results (2/2 tests passed)
- Verification of credit preservation during cancellation
- Idempotency testing results
- Production readiness assessment

## Running the Tests

```bash
# Run webhook cancellation tests
mix test test/rsolv/billing/webhook_cancellation_test.exs

# Run with verbose output (shows IO.puts statements)
mix test test/rsolv/billing/webhook_cancellation_test.exs --trace
```

## Related Files

- **Automated Test Suite:** `test/rsolv/billing/webhook_cancellation_test.exs` - Complete ExUnit tests with assertions and detailed output
