defmodule Rsolv.FeatureFlags do
  @moduledoc """
  Simple feature flag system for controlling pattern tier access.
  
  This module provides a way to dynamically control which pattern tiers
  are accessible to different customer segments without code changes.
  """
  
  # Default feature flag configuration
  # Can be overridden via environment variables or runtime configuration
  @default_flags %{
    # Pattern tier access flags
    "patterns.public.enabled" => true,
    "patterns.protected.enabled" => true,
    "patterns.ai.enabled" => true,
    "patterns.enterprise.enabled" => true,
    
    # Customer-specific overrides
    "patterns.ai.grant_all_authenticated" => true,  # Temporary: grant AI access to all authenticated users
    "patterns.enterprise.internal_only" => true,     # Enterprise tier only for internal/master customers
    
    # Tier inclusion flags (which tiers include lower tiers)
    "patterns.tier.cumulative" => true,              # Higher tiers include all lower tier patterns
    
    # Pattern source flags
    "patterns.use_compiled_modules" => true,         # Use compiled Elixir modules (vs database)
    "patterns.include_cve_patterns" => true,         # Include CVE patterns in results
    "patterns.include_framework_patterns" => true    # Include framework-specific patterns
  }
  
  @doc """
  Check if a feature flag is enabled.
  
  ## Examples
  
      iex> FeatureFlags.enabled?("patterns.public.enabled")
      true
      
      iex> FeatureFlags.enabled?("patterns.ai.grant_all_authenticated")
      true
  """
  def enabled?(flag_name) when is_binary(flag_name) do
    # First check environment variable
    env_key = "RSOLV_FLAG_" <> String.upcase(String.replace(flag_name, ".", "_"))
    
    case System.get_env(env_key) do
      "true" -> true
      "false" -> false
      "1" -> true
      "0" -> false
      nil ->
        # Fall back to application config
        case Application.get_env(:rsolv, :feature_flags, %{}) do
          %{^flag_name => value} -> value
          _ -> Map.get(@default_flags, flag_name, false)
        end
      _ -> false
    end
  end
  
  @doc """
  Get all flags with their current values.
  """
  def all_flags do
    # Merge defaults with configured values
    configured = Application.get_env(:rsolv, :feature_flags, %{})
    Map.merge(@default_flags, configured)
  end
  
  @doc """
  Check if a customer has access to a specific pattern tier.
  
  ## Examples
  
      iex> FeatureFlags.tier_access_allowed?("public", nil)
      true
      
      iex> FeatureFlags.tier_access_allowed?("ai", %{id: "123"})
      true  # When patterns.ai.grant_all_authenticated is true
  """
  def tier_access_allowed?(tier, customer) do
    base_flag = "patterns.#{tier}.enabled"
    
    # First check if the tier is enabled at all
    if enabled?(base_flag) do
      # Then check customer-specific rules
      case tier do
        "public" -> 
          true  # Public tier is always accessible when enabled
          
        "protected" -> 
          # Protected tier requires authentication
          not is_nil(customer)
          
        "ai" -> 
          # AI tier requires authentication and AI access
          not is_nil(customer) and 
          (enabled?("patterns.ai.grant_all_authenticated") or has_ai_flag?(customer))
          
        "enterprise" -> 
          # Enterprise tier has strict requirements
          not is_nil(customer) and
          (is_internal_customer?(customer) or has_enterprise_flag?(customer))
          
        _ -> 
          false
      end
    else
      false
    end
  end
  
  @doc """
  Get accessible tiers for a customer based on feature flags.
  """
  def get_accessible_tiers(customer) do
    all_tiers = ["public", "protected", "ai", "enterprise"]
    
    accessible = Enum.filter(all_tiers, fn tier ->
      tier_access_allowed?(tier, customer)
    end)
    
    # If cumulative tiers are enabled, ensure lower tiers are included
    if enabled?("patterns.tier.cumulative") do
      expand_tiers(accessible)
    else
      accessible
    end
  end
  
  # Private functions
  
  defp has_ai_flag?(%{flags: flags}) when is_list(flags) do
    "ai_access" in flags
  end
  defp has_ai_flag?(%{tier: "ai"}), do: true
  defp has_ai_flag?(%{tier: "enterprise"}), do: true
  defp has_ai_flag?(_), do: false
  
  defp has_enterprise_flag?(%{flags: flags}) when is_list(flags) do
    "enterprise_access" in flags
  end
  defp has_enterprise_flag?(%{tier: "enterprise"}), do: true
  defp has_enterprise_flag?(_), do: false
  
  defp is_internal_customer?(%{id: "internal"}), do: true
  defp is_internal_customer?(%{id: "master"}), do: true
  defp is_internal_customer?(%{email: email}) when is_binary(email) do
    String.ends_with?(email, "@rsolv.dev")
  end
  defp is_internal_customer?(_), do: false
  
  defp expand_tiers(tiers) do
    # Define tier hierarchy
    tier_order = ["public", "protected", "ai", "enterprise"]
    
    # Find the highest tier
    highest_index = tiers
    |> Enum.map(fn tier -> Enum.find_index(tier_order, &(&1 == tier)) || -1 end)
    |> Enum.max()
    
    if highest_index >= 0 do
      # Return all tiers up to and including the highest
      Enum.take(tier_order, highest_index + 1)
    else
      []
    end
  end
end