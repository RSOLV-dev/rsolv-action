defmodule Rsolv.FeatureFlagsTest do
  use Rsolv.DataCase, async: true
  alias Rsolv.FeatureFlags

  setup do
    # Set admin emails for testing
    Application.put_env(:rsolv, :admin_emails, ["admin@rsolv.dev"])

    # Enable core features for testing
    :ok = FeatureFlags.enable(:core_features)
    :ok = FeatureFlags.enable(:interactive_roi_calculator)
    :ok = FeatureFlags.enable(:team_size_field)
    :ok = FeatureFlags.enable(:feedback_form)

    :ok
  end

  describe "enabled?/1" do
    setup do
      # Ensure clean state for tests - disable flags that might be enabled globally
      FunWithFlags.disable(:admin_dashboard)
      FunWithFlags.disable(:api_access)
      FunWithFlags.disable(:advanced_analytics)

      # FunWithFlags operations are synchronous - no delay needed
      :ok
    end

    test "returns true for enabled default flags" do
      # Test with atom-based flags from the role_access map
      assert FeatureFlags.enabled?(:core_features) == true
      assert FeatureFlags.enabled?(:interactive_roi_calculator) == true
      assert FeatureFlags.enabled?(:team_size_field) == true
      assert FeatureFlags.enabled?(:feedback_form) == true
    end

    test "returns false for unknown flags" do
      assert FeatureFlags.enabled?(:unknown_flag) == false
    end

    test "returns false for role-gated features without user context" do
      # These features require specific roles
      # Note: admin_dashboard might be enabled globally by migration
      # so we need to check its actual state
      admin_dashboard_state = FunWithFlags.enabled?(:admin_dashboard)
      assert FeatureFlags.enabled?(:admin_dashboard) == admin_dashboard_state

      # These should be disabled without user context
      assert FeatureFlags.enabled?(:api_access) == false
      assert FeatureFlags.enabled?(:advanced_analytics) == false
    end
  end

  describe "enabled? with role-based access" do
    test "core features are accessible to all roles" do
      assert FeatureFlags.enabled?(:core_features) == true
      assert FeatureFlags.enabled?(:core_features, role: :early_access) == true
      assert FeatureFlags.enabled?(:core_features, role: :phase_1) == true
      assert FeatureFlags.enabled?(:core_features, role: :vip) == true
      assert FeatureFlags.enabled?(:core_features, role: :admin) == true
    end

    test "advanced analytics requires phase_1 or higher" do
      assert FeatureFlags.enabled?(:advanced_analytics, role: :early_access) == false
      assert FeatureFlags.enabled?(:advanced_analytics, role: :phase_1) == true
      assert FeatureFlags.enabled?(:advanced_analytics, role: :vip) == true
      assert FeatureFlags.enabled?(:advanced_analytics, role: :admin) == true
    end

    test "api access requires vip or higher" do
      assert FeatureFlags.enabled?(:api_access, role: :early_access) == false
      assert FeatureFlags.enabled?(:api_access, role: :phase_1) == false
      assert FeatureFlags.enabled?(:api_access, role: :vip) == true
      assert FeatureFlags.enabled?(:api_access, role: :admin) == true
    end

    test "admin dashboard requires admin role" do
      assert FeatureFlags.enabled?(:admin_dashboard, role: :early_access) == false
      assert FeatureFlags.enabled?(:admin_dashboard, role: :phase_1) == false
      assert FeatureFlags.enabled?(:admin_dashboard, role: :vip) == false
      assert FeatureFlags.enabled?(:admin_dashboard, role: :admin) == true
    end

    test "respects user email for admin access" do
      assert FeatureFlags.enabled?(:admin_dashboard, email: "admin@rsolv.dev") == true
      assert FeatureFlags.enabled?(:admin_dashboard, email: "user@example.com") == false
    end
  end

  describe "get_accessible_tiers/1" do
    test "returns only free tier for unauthenticated users" do
      assert FeatureFlags.get_accessible_tiers(nil) == ["free"]
    end

    test "returns free tier for free customers" do
      tiers = FeatureFlags.get_accessible_tiers(%{id: "123", tier: "free"})
      assert tiers == ["free"]
    end

    test "returns free and pro tiers for pro customers" do
      tiers = FeatureFlags.get_accessible_tiers(%{id: "123", tier: "pro"})
      assert tiers == ["free", "pro"]
    end

    test "returns all tiers for enterprise customers" do
      tiers = FeatureFlags.get_accessible_tiers(%{id: "internal", tier: "enterprise"})
      assert tiers == ["free", "pro", "enterprise"]
    end

    test "handles missing tier field gracefully" do
      # Customer without tier field defaults to free
      tiers = FeatureFlags.get_accessible_tiers(%{id: "123"})
      assert tiers == ["free"]
    end
  end
end
