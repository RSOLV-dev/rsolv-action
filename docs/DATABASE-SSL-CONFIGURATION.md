# Database SSL Configuration Guide

## Problem

When running RSOLV-api in Docker environments (especially for E2E testing), you may encounter SSL connection errors even when `DATABASE_SSL=false` is set:

```
[error] Postgrex.Protocol (#PID<0.2645.0>) failed to connect: ** (Postgrex.Error) ssl not available
```

## Root Cause

1. **Ecto Database URL Parsing**: When using `DATABASE_URL`, Ecto may attempt SSL connections based on URL parameters or defaults
2. **PostgreSQL Container**: The postgres:15-alpine image doesn't have SSL configured by default
3. **Configuration Precedence**: URL parameters can override environment variables

## Permanent Solution

### 1. Runtime Configuration (config/runtime.exs)

When `DATABASE_SSL=false`, explicitly set `ssl: false` in the database config:

```elixir
System.get_env("DATABASE_SSL") == "false" ->
  # Explicitly disable SSL to override any URL parameters
  Keyword.merge(database_config, [
    ssl: false
  ])
```

### 2. Database URL Format

Always include `?sslmode=disable` in PostgreSQL URLs for non-SSL environments:

```yaml
DATABASE_URL: postgresql://user:pass@host:port/db?sslmode=disable
```

### 3. Docker Compose Configuration

Set both the URL parameter and environment variable:

```yaml
environment:
  DATABASE_URL: postgresql://postgres:postgres@postgres:5432/rsolv_api_test?sslmode=disable
  DATABASE_SSL: "false"
```

## Testing

After applying these changes, run:

```bash
./run-e2e-docker.sh
```

The API should connect to PostgreSQL without SSL errors.

## Additional Notes

- This issue commonly occurs in test/development environments
- Production environments should use SSL when possible
- The fix is backward compatible with existing configurations