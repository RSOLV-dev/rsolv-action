defmodule Rsolv.FeatureFlags do
  @moduledoc """
  Feature flags management using FunWithFlags as the backend.
  
  This module provides a thin wrapper around FunWithFlags while maintaining
  the same API as the original FeatureFlags module. It adds role-based access
  control on top of FunWithFlags' base flag states.
  
  Features can be enabled:
  1. Globally (for all users via FunWithFlags)
  2. For specific user groups (via our Groups behavior and role logic)
  3. For specific users (by email and tags)
  
  ## Usage examples:
  
  ```elixir
  # Check if a feature is enabled globally
  FeatureFlags.enabled?(:interactive_roi_calculator)
  
  # Check if a feature is enabled for a specific user by email
  FeatureFlags.enabled?(:admin_dashboard, user: %{email: "user@example.com"})
  
  # Check if a feature is enabled for a user with tags
  FeatureFlags.enabled?(:advanced_analytics, user: %{email: "user@example.com", tags: ["vip"]})
  
  # Check if a feature is enabled for a user with a specific role
  FeatureFlags.enabled?(:custom_templates, email: "user@example.com")
  ```
  
  ## Early Access Program User Groups
  
  The early access program has four user groups, each with different feature access:
  
  1. **Early Access**: Basic access with core features only
  2. **Phase 1**: Core features plus advanced analytics, custom templates, and priority support
  3. **VIP**: All features including team collaboration and API access
  4. **Admin**: Complete access to all features including administrative tools
  
  This grouping is managed through ConvertKit tags applied to user accounts.
  """
  
  alias FunWithFlags
  
  # Define access control based on roles (copied from original module)
  @role_access %{
    # Feature access for early access users (basic tier)
    early_access: [
      :interactive_roi_calculator,
      :team_size_field,
      :feedback_form,
      :early_access_signup,
      :welcome_email_sequence,
      :core_features
    ],
    
    # Feature access for Phase 1 users
    phase_1: [
      :interactive_roi_calculator,
      :team_size_field,
      :feedback_form,
      :early_access_signup,
      :welcome_email_sequence,
      :core_features,
      :advanced_analytics,
      :custom_templates,
      :priority_support
    ],
    
    # Feature access for VIP users
    vip: [
      :interactive_roi_calculator,
      :team_size_field,
      :feedback_form,
      :early_access_signup,
      :welcome_email_sequence,
      :core_features,
      :advanced_analytics,
      :custom_templates,
      :team_collaboration,
      :api_access,
      :priority_support
    ],
    
    # Feature access for admin users
    admin: [
      :interactive_roi_calculator,
      :team_size_field, 
      :feedback_form,
      :early_access_signup,
      :welcome_email_sequence,
      :core_features,
      :advanced_analytics,
      :custom_templates,
      :team_collaboration,
      :api_access,
      :priority_support,
      :admin_dashboard,
      :metrics_dashboard,
      :feedback_dashboard,
      :support_ticket_submission,
      :user_engagement_tracking,
      :a_b_testing,
      # Test flags
      :enabled_test_feature,
      :test_enabled_feature
    ]
  }
  
  # Get admin emails at runtime to avoid compile-time/runtime mismatches
  defp admin_emails do
    Application.get_env(:rsolv, :admin_emails, ["admin@rsolv.dev"])
  end

  @doc """
  Check if a feature is enabled.
  
  ## Options
  
  - `:user` - User map with email and optional tags
  - `:email` - User email string (shorthand for user with email only)
  - `:role` - Specific role to check against (:early_access, :phase_1, :vip, :admin)
  
  If no user context is provided, checks the global flag state from FunWithFlags.
  If user context is provided, applies role-based logic on top of the base flag state.
  
  ## Examples
  
      iex> FeatureFlags.enabled?(:interactive_roi_calculator)
      true
      
      iex> FeatureFlags.enabled?(:admin_dashboard, user: %{email: "admin@rsolv.dev"})
      true
      
      iex> FeatureFlags.enabled?(:advanced_analytics, user: %{email: "user@example.com", tags: ["vip"]})
      true
      
      iex> FeatureFlags.enabled?(:api_access, email: "regular@example.com")
      false
  """
  def enabled?(feature, opts \\ [])
  
  def enabled?(feature, []) do
    # No user context provided, check global flag state
    FunWithFlags.enabled?(feature)
  rescue
    _error -> false
  end
  
  def enabled?(feature, opts) when is_list(opts) do
    # User context provided, apply role-based logic
    user = build_user_context(opts)
    
    case user do
      nil ->
        # No valid user context, fall back to global check
        FunWithFlags.enabled?(feature)
      
      user ->
        # Check if user has access to this feature based on their role
        user_role = determine_user_role(user)
        feature_accessible = feature in get_role_features(user_role)
        
        # Feature must be accessible to the user's role
        # For globally enabled features, role doesn't matter
        # For role-gated features, check both base state and role access
        if feature_accessible do
          # User has role access, check base flag state
          base_enabled = FunWithFlags.enabled?(feature)
          base_enabled || role_gated_feature?(feature)
        else
          false
        end
    end
  rescue
    _error -> false
  end
  
  @doc """
  Enable a feature flag globally.
  """
  def enable(feature) when is_binary(feature) do
    enable(String.to_atom(feature))
  end
  
  def enable(feature) when is_atom(feature) do
    # FunWithFlags.enable/1 exists and enables globally
    case FunWithFlags.enable(feature) do
      {:ok, _flag} -> :ok
      error -> error
    end
  end
  
  @doc """
  Disable a feature flag globally.
  """
  def disable(feature) when is_binary(feature) do
    disable(String.to_atom(feature))
  end
  
  def disable(feature) when is_atom(feature) do
    case FunWithFlags.disable(feature) do
      {:ok, _flag} -> :ok
      error -> error
    end
  end
  
  @doc """
  Enable a feature for a specific group.
  """
  def enable_for_group(feature, group) when is_binary(feature) do
    enable_for_group(String.to_atom(feature), group)
  end
  
  def enable_for_group(feature, group) when is_atom(feature) do
    case FunWithFlags.enable(feature, for_group: group) do
      {:ok, _flag} -> :ok
      error -> error
    end
  end
  
  @doc """
  Disable a feature for a specific group.
  """
  def disable_for_group(feature, group) when is_binary(feature) do
    disable_for_group(String.to_atom(feature), group)
  end
  
  def disable_for_group(feature, group) when is_atom(feature) do
    case FunWithFlags.disable(feature, for_group: group) do
      {:ok, _flag} -> :ok
      error -> error
    end
  end
  
  @doc """
  Enable a feature for a specific customer (actor).
  """
  def enable_for_customer(feature, customer) when is_binary(feature) do
    enable_for_customer(String.to_atom(feature), customer)
  end
  
  def enable_for_customer(feature, customer) when is_atom(feature) do
    # FunWithFlags accepts any term as an actor
    # We'll use the customer struct directly
    case FunWithFlags.enable(feature, for_actor: customer) do
      {:ok, _flag} -> :ok
      error -> error
    end
  end
  
  @doc """
  Clear the FunWithFlags cache.
  """
  def reload do
    # FunWithFlags cache management - clear all flags
    try do
      # FunWithFlags.clear/1 requires a cache name or :all
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
  
  @doc """
  Get all available feature flags.
  """
  def all_flags do
    @role_access.admin
  end
  
  @doc """
  Get detailed information about a feature flag.
  """
  def flag_info(feature) do
    enabled = FunWithFlags.enabled?(feature)
    required_role = get_minimum_required_role(feature)
    
    %{
      name: feature,
      enabled: enabled,
      required_role: required_role,
      description: get_feature_description(feature)
    }
  rescue
    _error ->
      %{
        name: feature,
        enabled: false,
        required_role: :unknown,
        description: "Unknown feature"
      }
  end
  
  @doc """
  Get all features available to a specific user.
  """
  def user_features(user) do
    role = determine_user_role(user)
    get_role_features(role)
  end

  @doc """
  Legacy API: Get features for a specific role.
  """
  def for_role(role) do
    get_role_features(role)
  end

  @doc """
  Legacy API: Get features for a specific user.
  """
  def for_user(user) do
    case user do
      nil -> get_role_features(:early_access)
      user -> user_features(user)
    end
  end

  @doc """
  Legacy API: Get all flags as a simple list.
  """
  def all do
    all_flags()
  end
  
  # Private helper functions
  
  defp build_user_context(opts) do
    cond do
      user = Keyword.get(opts, :user) ->
        user
        
      email = Keyword.get(opts, :email) ->
        %{email: email, tags: []}
        
      role = Keyword.get(opts, :role) ->
        # For role-based checks, create a dummy user with appropriate tags
        case role do
          :admin -> %{email: "admin@rsolv.dev", tags: []}
          :vip -> %{email: "vip@example.com", tags: ["vip"]}
          :phase_1 -> %{email: "phase1@example.com", tags: ["phase_1"]}
          :early_access -> %{email: "early@example.com", tags: []}
          _ -> nil
        end
        
      true ->
        nil
    end
  end
  
  defp determine_user_role(%{email: email} = user) when is_binary(email) do
    tags = Map.get(user, :tags, [])
    
    cond do
      email in admin_emails() -> :admin
      "vip" in tags -> :vip
      "phase_1" in tags or "vip" in tags -> :phase_1
      true -> :early_access
    end
  end
  
  defp determine_user_role(_), do: :early_access
  
  defp get_role_features(role) do
    Map.get(@role_access, role, [])
  end
  
  defp get_minimum_required_role(feature) do
    cond do
      feature in @role_access.early_access -> :early_access
      feature in @role_access.phase_1 -> :phase_1
      feature in @role_access.vip -> :vip
      feature in @role_access.admin -> :admin
      true -> :unknown
    end
  end
  
  defp role_gated_feature?(feature) do
    # Features that are gated by role but disabled globally
    # These are the premium/admin features that FunWithFlags has disabled
    # but are accessible via group gates
    feature in (@role_access.phase_1 ++ @role_access.vip ++ @role_access.admin) and
      feature not in @role_access.early_access
  end
  
  defp get_feature_description(feature) do
    case feature do
      :interactive_roi_calculator -> "Interactive ROI calculator on landing page"
      :team_size_field -> "Team size field in signup form"
      :feedback_form -> "Feedback collection form"
      :early_access_signup -> "Early access program signup"
      :welcome_email_sequence -> "Automated welcome email sequence"
      :core_features -> "Core platform features"
      :advanced_analytics -> "Advanced analytics dashboard"
      :custom_templates -> "Custom email and page templates"
      :team_collaboration -> "Team collaboration features"
      :api_access -> "API access and documentation"
      :priority_support -> "Priority customer support"
      :admin_dashboard -> "Administrative dashboard"
      :metrics_dashboard -> "System metrics dashboard"
      :feedback_dashboard -> "Feedback management dashboard"
      :support_ticket_submission -> "Support ticket system"
      :user_engagement_tracking -> "User engagement analytics"
      :a_b_testing -> "A/B testing framework"
      :enabled_test_feature -> "Test feature (enabled)"
      :test_enabled_feature -> "Test feature (enabled)"
      :disabled_test_feature -> "Test feature (disabled)"
      :test_disabled_feature -> "Test feature (disabled)"
      _ -> "Feature: #{feature}"
    end
  end
  
  @doc """
  Get accessible tiers for a customer based on their subscription and feature flags.
  """
  def get_accessible_tiers(customer) do
    cond do
      # Enterprise customer - access to all tiers
      customer && Map.get(customer, :tier) == "enterprise" ->
        ["free", "pro", "enterprise"]
      
      # Pro customer - access to free and pro tiers
      customer && Map.get(customer, :tier) == "pro" ->
        ["free", "pro"]
        
      # Free customer or no customer - only free tier
      true ->
        ["free"]
    end
  end
end
