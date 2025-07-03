defmodule Rsolv.FeatureFlagsMigration do
  @moduledoc """
  Migration script to move all static feature flags from the custom FeatureFlags
  module to FunWithFlags with proper gates and role-based access.
  
  This script:
  1. Seeds all 26 feature flags into FunWithFlags
  2. Sets up boolean gates for simple flags
  3. Configures group gates for role-based features
  4. Preserves existing default values and access controls
  
  Run with: Rsolv.FeatureFlagsMigration.migrate_all()
  """
  
  alias FunWithFlags
  
  # Original feature flags configuration (preserved for migration verification)
  defp get_original_feature_flags do
    %{
      # Landing page features
      interactive_roi_calculator: true,
      team_size_field: true,
      feedback_form: true,
      
      # Early access program features
      early_access_signup: true,
      welcome_email_sequence: true,
      
      # Core features (always enabled for early access)
      core_features: true,
      
      # Premium features (controlled by cohort)
      advanced_analytics: false,
      custom_templates: false,
      team_collaboration: false,
      api_access: false,
      priority_support: false,
      
      # Admin features
      admin_dashboard: false,
      metrics_dashboard: false,
      feedback_dashboard: false,
      
      # Beta features (disabled by default)
      support_ticket_submission: false,
      user_engagement_tracking: false,
      a_b_testing: false,
      
      # Test-only features
      enabled_test_feature: true,
      disabled_test_feature: false,
      test_enabled_feature: true,
      test_disabled_feature: false
    }
  end
  
  @doc """
  Migrates all feature flags from static configuration to FunWithFlags.
  Returns {:ok, results} with migration details or {:error, reason}.
  """
  def migrate_all do
    results = %{
      migrated: [],
      failed: [],
      total: 0
    }
    
    # Start with landing page features (all enabled by default)
    results = migrate_landing_page_features(results)
    
    # Early access features (all enabled by default)
    results = migrate_early_access_features(results)
    
    # Premium features (role-based access)
    results = migrate_premium_features(results)
    
    # Admin features (admin-only access)
    results = migrate_admin_features(results)
    
    # Beta features (all disabled by default)
    results = migrate_beta_features(results)
    
    # Test features
    results = migrate_test_features(results)
    
    # Print summary
    IO.puts("\n=== Feature Flags Migration Summary ===")
    IO.puts("Total flags processed: #{results.total}")
    IO.puts("Successfully migrated: #{length(results.migrated)}")
    IO.puts("Failed migrations: #{length(results.failed)}")
    
    if length(results.failed) > 0 do
      IO.puts("\nFailed flags:")
      Enum.each(results.failed, fn {flag, reason} ->
        IO.puts("  - #{flag}: #{inspect(reason)}")
      end)
    end
    
    {:ok, results}
  end
  
  @doc """
  Verifies all flags were migrated correctly by comparing with original configuration.
  """
  def verify_migration do
    # Get the flags from the original feature flags map before migration
    original_flags = get_original_feature_flags()
    
    IO.puts("\n=== Verifying Feature Flags Migration ===")
    
    Enum.each(original_flags, fn {flag, default_value} ->
      # Check basic flag existence and value
      fun_with_flags_value = FunWithFlags.enabled?(flag)
      
      if fun_with_flags_value == default_value do
        IO.puts("✓ #{flag}: matches default (#{default_value})")
      else
        IO.puts("✗ #{flag}: mismatch! Static: #{default_value}, FunWithFlags: #{fun_with_flags_value}")
      end
    end)
  end
  
  # Private migration functions for each category
  
  defp migrate_landing_page_features(results) do
    flags = [
      :interactive_roi_calculator,
      :team_size_field,
      :feedback_form
    ]
    
    migrate_flags(flags, :enable_globally, results, "Landing Page Features")
  end
  
  defp migrate_early_access_features(results) do
    flags = [
      :early_access_signup,
      :welcome_email_sequence,
      :core_features
    ]
    
    migrate_flags(flags, :enable_globally, results, "Early Access Features")
  end
  
  defp migrate_premium_features(results) do
    # Phase 1+ features
    phase_1_flags = [
      :advanced_analytics,
      :custom_templates,
      :priority_support
    ]
    
    # VIP+ features
    vip_flags = [
      :team_collaboration,
      :api_access
    ]
    
    results = migrate_flags(phase_1_flags, {:enable_for_groups, [:phase_1, :vip, :admin]}, results, "Phase 1 Features")
    migrate_flags(vip_flags, {:enable_for_groups, [:vip, :admin]}, results, "VIP Features")
  end
  
  defp migrate_admin_features(results) do
    flags = [
      :admin_dashboard,
      :metrics_dashboard,
      :feedback_dashboard
    ]
    
    migrate_flags(flags, {:enable_for_groups, [:admin]}, results, "Admin Features")
  end
  
  defp migrate_beta_features(results) do
    flags = [
      :support_ticket_submission,
      :user_engagement_tracking,
      :a_b_testing
    ]
    
    migrate_flags(flags, :disable_globally, results, "Beta Features")
  end
  
  defp migrate_test_features(results) do
    enabled_flags = [
      :enabled_test_feature,
      :test_enabled_feature
    ]
    
    disabled_flags = [
      :disabled_test_feature,
      :test_disabled_feature
    ]
    
    results = migrate_flags(enabled_flags, :enable_globally, results, "Test Features (Enabled)")
    migrate_flags(disabled_flags, :disable_globally, results, "Test Features (Disabled)")
  end
  
  # Helper function to migrate a list of flags with the same configuration
  defp migrate_flags(flags, action, results, category) do
    IO.puts("\nMigrating #{category}...")
    
    Enum.reduce(flags, results, fn flag, acc ->
      case migrate_single_flag(flag, action) do
        :ok ->
          IO.puts("  ✓ #{flag}")
          %{acc | migrated: [flag | acc.migrated], total: acc.total + 1}
          
        {:error, reason} ->
          IO.puts("  ✗ #{flag}: #{inspect(reason)}")
          %{acc | failed: [{flag, reason} | acc.failed], total: acc.total + 1}
      end
    end)
  end
  
  # Migrate a single flag based on the action
  defp migrate_single_flag(flag, :enable_globally) do
    case FunWithFlags.enable(flag) do
      {:ok, true} -> :ok
      {:ok, false} -> {:error, "Failed to enable flag"}
      error -> error
    end
  end
  
  defp migrate_single_flag(flag, :disable_globally) do
    case FunWithFlags.disable(flag) do
      {:ok, true} -> :ok
      {:ok, false} -> :ok  # Flag is already disabled, which is what we want
      error -> error
    end
  end
  
  defp migrate_single_flag(flag, {:enable_for_groups, groups}) do
    # First disable globally, then enable for specific groups
    with {:ok, _} <- FunWithFlags.disable(flag) do
      # Enable for each group
      Enum.reduce_while(groups, :ok, fn group, _acc ->
        case FunWithFlags.enable(flag, for_group: group) do
          {:ok, true} -> {:cont, :ok}
          {:ok, false} -> {:halt, {:error, "Failed to enable for group #{group}"}}
          error -> {:halt, error}
        end
      end)
    else
      error -> error
    end
  end
  
  @doc """
  Rolls back all migrated flags by clearing them from FunWithFlags.
  Use with caution - this will remove all flag configurations!
  """
  def rollback_all do
    IO.puts("\n=== Rolling Back Feature Flags ===")
    IO.puts("WARNING: This will remove all flag configurations from FunWithFlags!")
    IO.puts("Type 'yes' to confirm: ")
    
    case IO.gets("") |> String.trim() do
      "yes" ->
        all_flags = Rsolv.FeatureFlags.all_flags()
        
        Enum.each(all_flags, fn flag ->
          case FunWithFlags.clear(flag) do
            {:ok, _} -> IO.puts("  ✓ Cleared #{flag}")
            :ok -> IO.puts("  ✓ Cleared #{flag}")
            error -> IO.puts("  ✗ Failed to clear #{flag}: #{inspect(error)}")
          end
        end)
        
        IO.puts("\nRollback complete.")
        
      _ ->
        IO.puts("Rollback cancelled.")
    end
  end
  
  @doc """
  Displays current configuration for a specific flag in both systems.
  """
  def inspect_flag(flag) do
    IO.puts("\n=== Inspecting Flag: #{flag} ===")
    
    # Check static configuration
    static_enabled = Rsolv.FeatureFlags.enabled?(flag)
    IO.puts("Static FeatureFlags: #{static_enabled}")
    
    # Check FunWithFlags
    fun_flags_enabled = FunWithFlags.enabled?(flag)
    IO.puts("FunWithFlags (global): #{fun_flags_enabled}")
    
    # Check for different roles
    roles = [:early_access, :phase_1, :vip, :admin]
    IO.puts("\nRole-based access:")
    Enum.each(roles, fn role ->
      static_role = Rsolv.FeatureFlags.enabled?(flag, role: role)
      IO.puts("  #{role}: #{static_role} (static)")
    end)
    
    # Show which users have access
    IO.puts("\nExample user access:")
    test_users = [
      %{email: "user@example.com", tags: []},
      %{email: "phase1@example.com", tags: ["phase_1"]},
      %{email: "vip@example.com", tags: ["vip"]},
      %{email: "admin@rsolv.dev", tags: []}
    ]
    
    Enum.each(test_users, fn user ->
      static_access = Rsolv.FeatureFlags.enabled?(flag, user: user)
      fun_flags_access = FunWithFlags.enabled?(flag, for: %{id: user.email})
      IO.puts("  #{user.email}: static=#{static_access}, funwithflags=#{fun_flags_access}")
    end)
  end
end