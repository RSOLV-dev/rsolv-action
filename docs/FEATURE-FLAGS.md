# Pattern Tier Feature Flags

This document describes the feature flag system implemented for controlling pattern tier access in RSOLV-api.

## Overview

The feature flag system allows dynamic control over which security pattern tiers are accessible to different customer segments without requiring code changes or deployments.

## Available Feature Flags

### Pattern Tier Flags

- `patterns.public.enabled` - Enable/disable public tier patterns (default: true)
- `patterns.protected.enabled` - Enable/disable protected tier patterns (default: true)
- `patterns.ai.enabled` - Enable/disable AI tier patterns (default: true)
- `patterns.enterprise.enabled` - Enable/disable enterprise tier patterns (default: true)

### Access Control Flags

- `patterns.ai.grant_all_authenticated` - Grant AI tier access to all authenticated users (default: true)
- `patterns.enterprise.internal_only` - Restrict enterprise tier to internal users only (default: true)

### Behavior Flags

- `patterns.tier.cumulative` - Higher tiers include all lower tier patterns (default: true)
- `patterns.use_compiled_modules` - Use compiled Elixir modules vs database (default: true)
- `patterns.include_cve_patterns` - Include CVE patterns in results (default: true)
- `patterns.include_framework_patterns` - Include framework-specific patterns (default: true)

## Configuration Methods

### 1. Environment Variables

Feature flags can be overridden using environment variables:

```bash
# Disable public patterns
export RSOLV_FLAG_PATTERNS_PUBLIC_ENABLED=false

# Enable enterprise access for all
export RSOLV_FLAG_PATTERNS_ENTERPRISE_INTERNAL_ONLY=false

# Disable CVE patterns
export RSOLV_FLAG_PATTERNS_INCLUDE_CVE_PATTERNS=false
```

Environment variable format: `RSOLV_FLAG_` + flag name in uppercase with dots replaced by underscores.

### 2. Application Configuration

Flags can be set in the application config:

```elixir
# config/runtime.exs
config :rsolv_api, :feature_flags, %{
  "patterns.ai.grant_all_authenticated" => false,
  "patterns.enterprise.internal_only" => false
}
```

### 3. Default Values

Default values are defined in `lib/rsolv_api/feature_flags.ex`.

## Tier Access Logic

### Public Tier
- Always accessible when enabled
- No authentication required

### Protected Tier
- Requires API key authentication
- Accessible to all authenticated customers

### AI Tier
- Requires API key authentication
- By default, accessible to all authenticated users (controlled by `patterns.ai.grant_all_authenticated`)
- Can be restricted to customers with specific flags or tiers

### Enterprise Tier
- Requires API key authentication
- By default, only accessible to:
  - Customers with ID "internal" or "master"
  - Customers with @rsolv.dev email addresses
  - Customers with tier set to "enterprise"

## Admin API Endpoints

### List All Feature Flags
```bash
GET /api/v1/admin/feature-flags
Authorization: Bearer <admin-api-key>
```

Response:
```json
{
  "feature_flags": {
    "patterns.public.enabled": true,
    "patterns.protected.enabled": true,
    "patterns.ai.enabled": true,
    "patterns.enterprise.enabled": true,
    "patterns.ai.grant_all_authenticated": true,
    "patterns.enterprise.internal_only": true,
    "patterns.tier.cumulative": true,
    "patterns.use_compiled_modules": true,
    "patterns.include_cve_patterns": true,
    "patterns.include_framework_patterns": true
  },
  "environment_overrides": {
    "patterns.public.enabled": "false"
  }
}
```

### Check Specific Flag
```bash
GET /api/v1/admin/feature-flags/patterns.ai.enabled
Authorization: Bearer <admin-api-key>
```

Response:
```json
{
  "flag_name": "patterns.ai.enabled",
  "enabled": true,
  "source": "default"
}
```

## Usage in Code

### Check if a flag is enabled:
```elixir
if FeatureFlags.enabled?("patterns.include_cve_patterns") do
  # Include CVE patterns
end
```

### Check tier access for a customer:
```elixir
if FeatureFlags.tier_access_allowed?("ai", customer) do
  # Grant AI tier access
end
```

### Get all accessible tiers for a customer:
```elixir
tiers = FeatureFlags.get_accessible_tiers(customer)
# Returns: ["public", "protected", "ai"]
```

## Testing

Run the feature flag tests:
```bash
mix test test/rsolv_api/feature_flags_test.exs
```

## Future Enhancements

1. **Dynamic Updates**: Add ability to update flags at runtime without restart
2. **A/B Testing**: Support percentage-based rollouts
3. **Customer Overrides**: Allow per-customer flag overrides
4. **Audit Logging**: Track flag changes and access
5. **UI Dashboard**: Web interface for managing flags
6. **Webhooks**: Notify services when flags change