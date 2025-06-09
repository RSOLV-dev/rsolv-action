defmodule RsolvApi.FeatureFlagsTest do
  use ExUnit.Case, async: true
  alias RsolvApi.FeatureFlags
  
  describe "enabled?/1" do
    test "returns true for enabled default flags" do
      assert FeatureFlags.enabled?("patterns.public.enabled") == true
      assert FeatureFlags.enabled?("patterns.protected.enabled") == true
      assert FeatureFlags.enabled?("patterns.ai.enabled") == true
      assert FeatureFlags.enabled?("patterns.enterprise.enabled") == true
    end
    
    test "returns false for unknown flags" do
      assert FeatureFlags.enabled?("unknown.flag") == false
    end
    
    test "respects environment variable overrides" do
      # Set environment variable
      System.put_env("RSOLV_FLAG_PATTERNS_PUBLIC_ENABLED", "false")
      assert FeatureFlags.enabled?("patterns.public.enabled") == false
      
      # Clean up
      System.delete_env("RSOLV_FLAG_PATTERNS_PUBLIC_ENABLED")
    end
  end
  
  describe "tier_access_allowed?/2" do
    test "public tier is accessible without authentication" do
      assert FeatureFlags.tier_access_allowed?("public", nil) == true
    end
    
    test "protected tier requires authentication" do
      assert FeatureFlags.tier_access_allowed?("protected", nil) == false
      assert FeatureFlags.tier_access_allowed?("protected", %{id: "123"}) == true
    end
    
    test "ai tier requires authentication" do
      assert FeatureFlags.tier_access_allowed?("ai", nil) == false
      
      # With grant_all_authenticated enabled (default)
      assert FeatureFlags.tier_access_allowed?("ai", %{id: "123"}) == true
    end
    
    test "enterprise tier requires special access" do
      assert FeatureFlags.tier_access_allowed?("enterprise", nil) == false
      assert FeatureFlags.tier_access_allowed?("enterprise", %{id: "123"}) == false
      
      # Internal customers have access
      assert FeatureFlags.tier_access_allowed?("enterprise", %{id: "internal"}) == true
      assert FeatureFlags.tier_access_allowed?("enterprise", %{id: "master"}) == true
      assert FeatureFlags.tier_access_allowed?("enterprise", %{email: "user@rsolv.dev"}) == true
    end
    
    test "respects tier-specific flags" do
      assert FeatureFlags.tier_access_allowed?("enterprise", %{tier: "enterprise"}) == true
      assert FeatureFlags.tier_access_allowed?("ai", %{tier: "ai"}) == true
    end
  end
  
  describe "get_accessible_tiers/1" do
    test "returns only public for unauthenticated users" do
      assert FeatureFlags.get_accessible_tiers(nil) == ["public"]
    end
    
    test "returns public and protected for authenticated users" do
      tiers = FeatureFlags.get_accessible_tiers(%{id: "123"})
      assert "public" in tiers
      assert "protected" in tiers
    end
    
    test "includes ai tier for authenticated users with default settings" do
      tiers = FeatureFlags.get_accessible_tiers(%{id: "123"})
      assert "ai" in tiers
    end
    
    test "includes enterprise tier for internal users" do
      tiers = FeatureFlags.get_accessible_tiers(%{id: "internal"})
      assert "enterprise" in tiers
    end
    
    test "cumulative tiers include all lower tiers" do
      # Enterprise user should get all tiers
      tiers = FeatureFlags.get_accessible_tiers(%{id: "internal"})
      assert tiers == ["public", "protected", "ai", "enterprise"]
    end
  end
end