# Lessons Learned: Production Outage 2025-09-17

## Summary
Complete production outage caused by missing database tables, empty secrets, and misconfigured environment variables. Service was down for ~30 minutes with credential vending completely broken.

## Root Causes

### 1. Missing Environment Variables in K8s Deployment
**What broke**: AI provider API keys weren't mounted as environment variables
**Impact**: Credential vending returned mock keys instead of real ones
**What TDD would have caught**:
```elixir
# test/rsolv_web/controllers/credential_controller_test.exs
describe "credential exchange" do
  test "returns actual AI provider credentials, not mock keys" do
    conn = post(conn, "/api/v1/credentials/exchange", %{providers: ["anthropic"]})
    response = json_response(conn, 200)

    refute response["credentials"]["anthropic"]["api_key"] =~ "mock"
    assert response["credentials"]["anthropic"]["api_key"] =~ "sk-ant"
  end
end
```

### 2. Missing Database Tables
**What broke**: Multiple tables didn't exist (api_keys, customers, analytics_events, fun_with_flags_toggles)
**Impact**: 500 errors on all API requests
**What TDD would have caught**:
```elixir
# test/rsolv/repo_test.exs
describe "database schema" do
  test "all required tables exist" do
    required_tables = ["api_keys", "customers", "analytics_events", "fun_with_flags_toggles"]

    for table <- required_tables do
      query = "SELECT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = $1)"
      {:ok, %{rows: [[exists]]}} = Repo.query(query, [table])
      assert exists, "Table #{table} must exist"
    end
  end

  test "customers table has all required columns" do
    {:ok, columns} = Repo.query("""
      SELECT column_name, data_type
      FROM information_schema.columns
      WHERE table_name = 'customers'
    """)

    required_columns = %{
      "admin_level" => "character varying",
      "metadata" => "jsonb",
      "is_staff" => "boolean",
      "monthly_limit" => "integer"
    }

    for {col, type} <- required_columns do
      assert {col, type} in columns.rows, "Column #{col} with type #{type} missing"
    end
  end
end
```

### 3. Empty Critical Secrets
**What broke**: SECRET_KEY_BASE, LIVE_VIEW_SALT were empty (0 bytes)
**Impact**: Phoenix refused to start, health checks failed
**What TDD would have caught**:
```elixir
# test/config_test.exs
describe "required configuration" do
  test "SECRET_KEY_BASE is properly configured" do
    secret = Application.get_env(:rsolv, RsolvWeb.Endpoint)[:secret_key_base]
    assert byte_size(secret) >= 64, "SECRET_KEY_BASE must be at least 64 bytes"
  end

  test "AI provider keys are configured" do
    assert System.get_env("ANTHROPIC_API_KEY") != nil
    assert System.get_env("OPENAI_API_KEY") != nil
  end
end
```

### 4. Wrong Database Name in DATABASE_URL
**What broke**: DATABASE_URL pointed to rsolv_landing_prod instead of rsolv_platform_prod
**Impact**: Connection failures, service wouldn't start
**What TDD would have caught**:
```elixir
# test/database_config_test.exs
test "DATABASE_URL points to correct database" do
  url = System.get_env("DATABASE_URL")
  assert url =~ "rsolv_platform_prod", "Must use platform database, not landing"
end
```

## Missing Test Suites

### 1. Deployment Configuration Tests
```yaml
# .github/workflows/test-deployment.yml
name: Test Deployment Configuration
on: [push]
jobs:
  test-k8s-config:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Validate K8s manifests
        run: |
          # Check all required env vars are mounted
          kubectl apply --dry-run=client -f RSOLV-infrastructure/services/unified/overlays/production/

      - name: Check secret references
        run: |
          # Ensure all secretKeyRef entries reference existing keys
          yq eval '.spec.template.spec.containers[].env[].valueFrom.secretKeyRef' \
            RSOLV-infrastructure/services/unified/overlays/production/deployment-patch.yaml | \
            xargs -I {} kubectl get secret rsolv-secrets -o jsonpath='{.data.{}}' --dry-run=client
```

### 2. Integration Tests for Credential Vending
```typescript
// RSOLV-action/tests/integration/credential-vending.test.ts
describe('Credential Vending E2E', () => {
  it('should exchange RSOLV key for real AI credentials', async () => {
    const response = await fetch(`${API_URL}/api/v1/credentials/exchange`, {
      method: 'POST',
      headers: {
        'x-api-key': process.env.RSOLV_API_KEY,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ providers: ['anthropic'], ttl_minutes: 60 })
    });

    expect(response.status).toBe(200);
    const data = await response.json();
    expect(data.credentials.anthropic.api_key).toMatch(/^sk-ant/);
    expect(data.credentials.anthropic.api_key).not.toContain('mock');
  });
});
```

### 3. Database Migration Tests
```elixir
# test/migrations_test.exs
defmodule Rsolv.MigrationsTest do
  use Rsolv.DataCase

  describe "production readiness" do
    test "all migrations have been run" do
      {:ok, result} = Repo.query("SELECT COUNT(*) FROM schema_migrations")
      [[count]] = result.rows

      migration_files = Path.wildcard("priv/repo/migrations/*.exs")
      assert count == length(migration_files), "All migrations must be run"
    end

    test "no pending migrations" do
      {output, 0} = System.cmd("mix", ["ecto.migrations"])
      refute output =~ "down", "No migrations should be pending"
    end
  end
end
```

### 4. Health Check Tests
```elixir
# test/health_check_test.exs
defmodule RsolvWeb.HealthCheckTest do
  use RsolvWeb.ConnCase

  test "health endpoint validates all dependencies", %{conn: conn} do
    conn = get(conn, "/api/health")
    response = json_response(conn, 200)

    assert response["status"] == "healthy"
    assert response["services"]["database"] == "healthy"
    assert response["services"]["ai_providers"]["anthropic"] == "healthy"

    # Should fail if any critical component is unhealthy
    refute response["phoenix_config"]["status"] == "error"
    refute response["analytics"]["status"] == "error"
  end
end
```

## What We Should Have Done

### 1. Pre-Deployment Checklist Tests
```bash
#!/bin/bash
# scripts/pre-deploy-check.sh

echo "Running pre-deployment checks..."

# 1. Test database connectivity
psql $DATABASE_URL -c "SELECT 1" || exit 1

# 2. Verify all required tables exist
for table in api_keys customers analytics_events; do
  psql $DATABASE_URL -c "SELECT 1 FROM $table LIMIT 1" || exit 1
done

# 3. Check all secrets are non-empty
for secret in SECRET_KEY_BASE ANTHROPIC_API_KEY OPENAI_API_KEY; do
  [ -z "${!secret}" ] && echo "ERROR: $secret is empty" && exit 1
done

# 4. Test credential exchange
curl -f -X POST $API_URL/api/v1/credentials/exchange \
  -H "x-api-key: $RSOLV_API_KEY" \
  -d '{"providers":["anthropic"]}' || exit 1

echo "All checks passed!"
```

### 2. Continuous Monitoring Tests
```typescript
// monitoring/credential-vending-monitor.ts
setInterval(async () => {
  try {
    const response = await testCredentialExchange();
    if (!response.ok || response.data.credentials.anthropic.api_key.includes('mock')) {
      alertOncall('Credential vending is returning mock keys!');
    }
  } catch (error) {
    alertOncall('Credential vending is down!', error);
  }
}, 60000); // Every minute
```

## Action Items

1. **Immediate**:
   - [ ] Add pre-deployment validation script
   - [ ] Create integration test suite for credential vending
   - [ ] Add GitHub Action to validate K8s configurations

2. **This Week**:
   - [ ] Implement comprehensive health check tests
   - [ ] Add database schema validation tests
   - [ ] Set up continuous monitoring for critical paths

3. **This Month**:
   - [ ] Full TDD implementation for all new features
   - [ ] Retrofit tests for existing critical paths
   - [ ] Set up staging environment that mirrors production exactly

## The TDD Way Forward

```markdown
For every bug we found today, we should have had:
1. A failing test that demonstrates the bug
2. A fix that makes the test pass
3. A refactor to make the fix clean
4. A review to ensure we didn't break anything else

The pattern:
- RED: Write a test that fails (proves the bug exists)
- GREEN: Make it pass (fix the bug)
- REFACTOR: Clean up the implementation
- REVIEW: Ensure no regression
```

## Cost of Not Having TDD

- **Time lost**: 30+ minutes of downtime
- **Debugging time**: 1+ hour of investigation
- **Risk**: Credential vending sending mock keys to production
- **Trust**: Users experienced 503 errors
- **Opportunity cost**: Could have been building features instead of firefighting

## Quote to Remember

> "The best time to write a test was before deploying to production. The second best time is now."

We need to treat tests as first-class citizens, not afterthoughts.