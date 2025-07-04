# FunWithFlags Caching Behavior Documentation

## Overview

FunWithFlags is used in the RSOLV platform for feature flag management. This document summarizes the caching behavior and known configurations based on the codebase analysis.

## Current Configuration

### 1. Persistence Layer
- **Adapter**: `FunWithFlags.Store.Persistent.Ecto`
- **Repository**: `Rsolv.Repo`
- **Configuration**: Found in `config/config.exs`

### 2. Cache Bust Notifications
- **Status**: DISABLED
- **Configuration**: `config :fun_with_flags, :cache_bust_notifications, enabled: false`
- **Location**: `config/config.exs` line 86

**Important**: This means that when feature flags are changed in the database, the cache is NOT automatically invalidated across nodes.

### 3. ETS Cache
- **Table Name**: `:fun_with_flags_cache`
- **Type**: Local ETS cache per node
- **Clear Method**: Manual clearing via `Rsolv.Cluster.clear_local_cache/0`

## Cache Management Implementation

### Manual Cache Clearing
The `Rsolv.FeatureFlags` module provides a `reload/0` function to manually clear the cache:

```elixir
def reload do
  # FunWithFlags cache management - clear all flags
  try do
    FunWithFlags.clear(:all)
    :ok
  rescue
    _error ->
      # If clear/1 doesn't exist, try clearing all known flags individually
      try do
        all_flags()
        |> Enum.each(&FunWithFlags.clear(&1))
        :ok
      rescue
        _error -> :ok
      end
  end
end
```

### Distributed Cache Invalidation
The `Rsolv.Cluster` module supports distributed cache invalidation:

1. **Broadcast Method**: `Rsolv.Cluster.broadcast({:invalidate_feature_flags_cache})`
2. **Handler**: Clears the local ETS cache on each node
3. **Implementation**: Found in `lib/rsolv/cluster.ex` lines 125-143

```elixir
def handle_broadcast(message) do
  case message do
    {:invalidate_feature_flags_cache} ->
      # Clear the FunWithFlags cache on this node
      clear_local_cache()
    _ ->
      Logger.debug("Unknown broadcast message: #{inspect(message)}")
  end
end

defp clear_local_cache do
  # This will clear the ETS cache used by FunWithFlags
  try do
    :ets.delete_all_objects(:fun_with_flags_cache)
    Logger.info("Feature flags cache cleared")
  rescue
    error ->
      Logger.error("Failed to clear cache: #{inspect(error)}")
  end
end
```

## Known Issues and Considerations

### 1. Cache Persistence Across Deployments
- Since cache bust notifications are disabled, feature flag changes may not propagate immediately
- Cached values persist until manually cleared or the node restarts
- This can lead to inconsistent behavior across nodes in a cluster

### 2. Module Name Inconsistencies
The codebase has several module naming issues related to FunWithFlags:
- Test support files still reference old `RsolvLanding` module names
- Files affected:
  - `test/support/feature_flag_case.ex`
  - `test/support/feature_flags_helper.ex`
  - `test/support/fun_with_flags_helper.ex`
  - `test/support/fun_with_flags_helpers.ex`
- Migration file uses old module name: `priv/repo/migrations/20250531_create_fun_with_flags_tables.exs`

### 3. Clustering Support
- The platform supports BEAM clustering for distributed environments
- Clustering strategies: Kubernetes and DNS-based
- Cache invalidation requires manual broadcasting or node restarts

## Recommendations

1. **Enable Cache Bust Notifications**: Consider enabling cache bust notifications for automatic propagation:
   ```elixir
   config :fun_with_flags, :cache_bust_notifications, enabled: true
   ```

2. **Implement Automatic Cache Invalidation**: When feature flags are modified through admin interfaces, automatically broadcast cache invalidation:
   ```elixir
   # After flag modification
   Rsolv.Cluster.broadcast({:invalidate_feature_flags_cache})
   ```

3. **Fix Module Naming**: Update test support files to use correct module names (from `RsolvLanding` to `RSOLV` or `Rsolv`)

4. **Document Cache TTL**: Consider implementing a TTL-based cache invalidation strategy if real-time updates aren't critical

## Related Files
- Feature Flags Implementation: `lib/rsolv/feature_flags.ex`
- Cluster Management: `lib/rsolv/cluster.ex`
- Configuration: `config/config.exs`
- Test Helpers: `test/support/fun_with_flags_*.ex`

## Future Considerations
- RFC-032 proposes using Mnesia for distributed caching, which could replace or complement the current FunWithFlags caching strategy
- Consider implementing a hybrid approach with local ETS cache and distributed Mnesia cache for better performance and consistency