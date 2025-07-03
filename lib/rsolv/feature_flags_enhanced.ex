defmodule Rsolv.FeatureFlagsEnhanced do
  @moduledoc """
  Enhanced feature flags module with cluster-aware cache invalidation.
  
  This module wraps the standard FeatureFlags module to add:
  - Cluster-wide cache invalidation on flag changes
  - Immediate cache clearing after updates
  - Better handling of authentication-required routes
  """
  
  require Logger
  alias Rsolv.{FeatureFlags, Cluster}
  
  @doc """
  Enables a feature flag and invalidates cache across the cluster
  """
  def enable(flag_name) do
    result = FunWithFlags.enable(flag_name)
    invalidate_cache_cluster_wide()
    result
  end
  
  @doc """
  Disables a feature flag and invalidates cache across the cluster
  """
  def disable(flag_name) do
    result = FunWithFlags.disable(flag_name)
    invalidate_cache_cluster_wide()
    result
  end
  
  @doc """
  Enables a flag for a specific group and invalidates cache
  """
  def enable_for_group(flag_name, group) do
    result = FunWithFlags.enable(flag_name, for_group: group)
    invalidate_cache_cluster_wide()
    result
  end
  
  @doc """
  Disables a flag for a specific group and invalidates cache
  """
  def disable_for_group(flag_name, group) do
    result = FunWithFlags.disable(flag_name, for_group: group)
    invalidate_cache_cluster_wide()
    result
  end
  
  @doc """
  Enables a flag for a specific actor and invalidates cache
  """
  def enable_for_actor(flag_name, actor) do
    result = FunWithFlags.enable(flag_name, for_actor: actor)
    invalidate_cache_cluster_wide()
    result
  end
  
  @doc """
  Disables a flag for a specific actor and invalidates cache
  """
  def disable_for_actor(flag_name, actor) do
    result = FunWithFlags.disable(flag_name, for_actor: actor)
    invalidate_cache_cluster_wide()
    result
  end
  
  @doc """
  Clears all flags and invalidates cache
  """
  def clear_all do
    result = FunWithFlags.clear(fn _ -> true end)
    invalidate_cache_cluster_wide()
    result
  end
  
  @doc """
  Force a cache invalidation across the entire cluster
  """
  def invalidate_cache_cluster_wide do
    # Clear local cache immediately
    clear_local_cache()
    
    # Broadcast to all other nodes to clear their caches
    if Cluster.clustering_enabled?() do
      Cluster.broadcast({:invalidate_feature_flags_cache})
      Logger.info("Broadcasted cache invalidation to cluster")
    end
  end
  
  @doc """
  Clears the local FunWithFlags cache
  """
  def clear_local_cache do
    # Try multiple approaches to clear the cache
    
    # 1. Try to clear the ETS table directly
    try do
      :ets.delete_all_objects(:fun_with_flags_cache)
      Logger.debug("Cleared :fun_with_flags_cache ETS table")
    rescue
      _ -> :ok
    end
    
    # 2. Try using Phoenix.PubSub to notify local subscribers
    Phoenix.PubSub.broadcast(
      Rsolv.PubSub,
      "fun_with_flags_changes",
      {:fun_with_flags, :cache_bust, :all}
    )
    
    Logger.info("Local feature flags cache cleared")
  end
  
  @doc """
  Checks if a feature is enabled with immediate cache check.
  This bypasses the cache for critical checks.
  """
  def enabled_no_cache?(flag_name, opts \\ []) do
    # Force a fresh read from the database
    clear_local_cache()
    FeatureFlags.enabled?(flag_name, opts)
  end
  
  @doc """
  Migration helper to enable admin features for initial setup
  """
  def enable_admin_features do
    # Enable all admin features globally for initial access
    admin_features = [
      :admin_dashboard,
      :metrics_dashboard,
      :feedback_dashboard
    ]
    
    Enum.each(admin_features, fn feature ->
      enable(feature)
      Logger.info("Enabled #{feature} globally")
    end)
    
    invalidate_cache_cluster_wide()
    :ok
  end
end