defmodule Rsolv.FeatureFlagsCacheTest do
  use Rsolv.DataCase

  describe "feature flags cache invalidation" do
    test "flag changes are immediately visible" do
      # Enable a flag
      FunWithFlags.enable(:test_flag)

      # Check it's enabled
      assert FunWithFlags.enabled?(:test_flag)

      # The flag should still be enabled
      assert FunWithFlags.enabled?(:test_flag)

      # Clean up
      FunWithFlags.disable(:test_flag)
    end

    test "cache bust notifications are properly configured" do
      # Check if notifications are enabled
      config = Application.get_env(:fun_with_flags, :cache_bust_notifications)

      # This will fail initially (RED phase)
      assert config[:enabled] == true
      assert config[:adapter] == FunWithFlags.Notifications.PhoenixPubSub
    end

    test "Phoenix.PubSub is properly configured" do
      # Verify PubSub is running
      assert Process.whereis(Rsolv.PubSub) != nil

      # Verify we can subscribe to the topic
      assert :ok = Phoenix.PubSub.subscribe(Rsolv.PubSub, "fun_with_flags_changes")

      # In test environment, cache is disabled, so notifications won't be sent
      # But in dev/prod, they will work
    end
  end
end
