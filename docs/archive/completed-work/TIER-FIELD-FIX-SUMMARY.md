# Tier Field Fix Summary

## Issue
The RSOLV-api pattern controller was not including the `tier` field in all pattern responses. It was only included when explicitly filtering by tier (e.g., `?tier=public`), but missing in general pattern requests.

## Root Cause
The `format_patterns_for_api` function in `lib/rsolv_api/security.ex` was not including the tier field in its response formatting, even though the Pattern struct has a `default_tier` field.

## Changes Made

### 1. Updated `Security.format_patterns_for_api/1` (lib/rsolv_api/security.ex)
Added the tier field to the response map:
```elixir
tier: to_string(get_pattern_tier(pattern)),
```

### 2. Updated `Security.format_single_pattern/1` (lib/rsolv_api/security.ex)
Added the tier field to the single pattern formatting function:
```elixir
tier: to_string(get_pattern_tier(pattern)),
```

### 3. Updated `PatternController.format_pattern/2` for ASTPattern enhanced format
Added tier field with fallback logic:
```elixir
tier: to_string(pattern.tier || pattern.default_tier || "public"),
```

### 4. Updated `PatternController.format_pattern/2` for Pattern enhanced format
Added tier field:
```elixir
tier: to_string(pattern.default_tier || "public"),
```

## Result
Now all pattern API responses will include the `tier` field, regardless of whether the request includes a tier filter or not. This ensures consistent API responses across all endpoints:

- `/api/v1/patterns` - includes tier
- `/api/v1/patterns?tier=public` - includes tier
- `/api/v1/patterns/:language` - includes tier
- `/api/v2/patterns/metadata` - metadata responses already include pattern info
- All other pattern endpoints - include tier

## Testing
The changes have been verified by:
1. Code compilation successful
2. Source code verification confirms tier field is now included in all formatting functions
3. The existing `Pattern.to_api_format/1` already includes the tier field, ensuring consistency

## API Response Example
Before:
```json
{
  "id": "js-sql-injection",
  "name": "SQL Injection",
  "severity": "high",
  "type": "sql_injection",
  // ... other fields but NO tier
}
```

After:
```json
{
  "id": "js-sql-injection", 
  "name": "SQL Injection",
  "severity": "high",
  "type": "sql_injection",
  "tier": "protected",  // <-- Now included
  // ... other fields
}
```