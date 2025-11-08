defmodule RsolvWeb.Helpers.RateLimitHelperTest do
  use ExUnit.Case, async: false
  doctest RsolvWeb.Helpers.RateLimitHelper

  alias Rsolv.RateLimiter
  alias RsolvWeb.Helpers.RateLimitHelper

  setup do
    # Reset rate limiter before each test
    RateLimiter.reset()
    :ok
  end

  describe "check_and_format/2" do
    test "returns ok when within rate limit" do
      assert {:ok, metadata} = RateLimitHelper.check_and_format("test-ip", :customer_onboarding)
      assert is_map(metadata)
      assert Map.has_key?(metadata, :limit)
      assert Map.has_key?(metadata, :remaining)
      assert Map.has_key?(metadata, :reset)
    end

    test "returns error with formatted message when rate limited" do
      # Exhaust the rate limit (default is 10 for customer_onboarding)
      for _ <- 1..10 do
        RateLimiter.check_rate_limit("test-ip-2", :customer_onboarding)
      end

      assert {:error, :rate_limited, message, metadata} =
               RateLimitHelper.check_and_format("test-ip-2", :customer_onboarding)

      assert message =~ "Too many signup attempts"
      assert message =~ "Please try again in"
      assert is_map(metadata)
    end
  end

  describe "format_rate_limit_message/2" do
    test "formats message with minutes when > 1 minute" do
      future_time = System.system_time(:second) + 150
      metadata = %{reset: future_time}

      message = RateLimitHelper.format_rate_limit_message(:customer_onboarding, metadata)

      assert message =~ "Too many signup attempts"
      assert message =~ "2 minutes"
    end

    test "formats message with 1 minute" do
      future_time = System.system_time(:second) + 75
      metadata = %{reset: future_time}

      message = RateLimitHelper.format_rate_limit_message(:customer_onboarding, metadata)

      assert message =~ "1 minute"
    end

    test "formats message with seconds when < 1 minute" do
      future_time = System.system_time(:second) + 45
      metadata = %{reset: future_time}

      message = RateLimitHelper.format_rate_limit_message(:customer_onboarding, metadata)

      assert message =~ "45 seconds"
    end

    test "uses correct action description" do
      metadata = %{reset: System.system_time(:second) + 60}

      assert RateLimitHelper.format_rate_limit_message(:customer_onboarding, metadata) =~
               "signup attempts"

      assert RateLimitHelper.format_rate_limit_message(:auth_attempt, metadata) =~
               "login attempts"

      assert RateLimitHelper.format_rate_limit_message(:credential_exchange, metadata) =~
               "credential exchange attempts"
    end
  end
end
