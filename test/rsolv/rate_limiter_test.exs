defmodule Rsolv.RateLimiterTest do
  use ExUnit.Case, async: false
  
  alias Rsolv.RateLimiter
  
  setup do
    # Ensure rate limiter is started
    case Process.whereis(RateLimiter) do
      nil -> 
        {:ok, _pid} = RateLimiter.start_link([])
      _ -> 
        :ok
    end
    
    # Reset rate limiter before each test
    RateLimiter.reset()
    :ok
  end
  
  describe "check_rate_limit/2" do
    test "allows requests under the rate limit" do
      customer_id = "test-customer"
      action = "test-action"
      
      # First 100 requests should be allowed
      for i <- 1..100 do
        assert :ok = RateLimiter.check_rate_limit(customer_id, action),
               "Request #{i} should be allowed"
      end
    end
    
    test "blocks requests over the rate limit" do
      customer_id = "test-customer"
      action = "test-action"
      
      # First 100 requests should be allowed
      for _ <- 1..100 do
        assert :ok = RateLimiter.check_rate_limit(customer_id, action)
      end
      
      # 101st request should be blocked
      assert {:error, :rate_limited} = RateLimiter.check_rate_limit(customer_id, action)
    end
    
    test "uses separate counters per customer" do
      # Customer 1 uses their full quota
      for _ <- 1..100 do
        assert :ok = RateLimiter.check_rate_limit("customer-1", "action")
      end
      assert {:error, :rate_limited} = RateLimiter.check_rate_limit("customer-1", "action")
      
      # Customer 2 should still have their full quota
      for _ <- 1..100 do
        assert :ok = RateLimiter.check_rate_limit("customer-2", "action")
      end
      assert {:error, :rate_limited} = RateLimiter.check_rate_limit("customer-2", "action")
    end
    
    test "uses separate counters per action" do
      customer_id = "test-customer"
      
      # Use full quota for action 1
      for _ <- 1..100 do
        assert :ok = RateLimiter.check_rate_limit(customer_id, "action-1")
      end
      assert {:error, :rate_limited} = RateLimiter.check_rate_limit(customer_id, "action-1")
      
      # Should still have full quota for action 2
      for _ <- 1..100 do
        assert :ok = RateLimiter.check_rate_limit(customer_id, "action-2")
      end
      assert {:error, :rate_limited} = RateLimiter.check_rate_limit(customer_id, "action-2")
    end
    
    test "resets counter after 60 seconds" do
      customer_id = "test-customer"
      action = "test-action"
      
      # Use full quota
      for _ <- 1..100 do
        assert :ok = RateLimiter.check_rate_limit(customer_id, action)
      end
      assert {:error, :rate_limited} = RateLimiter.check_rate_limit(customer_id, action)
      
      # Mock time passage by directly manipulating Mnesia
      # This is a bit hacky but avoids sleeping for 60 seconds
      key = {customer_id, action}
      :mnesia.transaction(fn ->
        [{:rsolv_rate_limiter, ^key, count, _window}] = :mnesia.read(:rsolv_rate_limiter, key)
        :mnesia.write({:rsolv_rate_limiter, key, count, System.system_time(:second) - 61})
      end)
      
      # Should be allowed again
      assert :ok = RateLimiter.check_rate_limit(customer_id, action)
    end
    
    test "emits telemetry events" do
      customer_id = "test-customer"
      action = "test-action"
      
      # Attach telemetry handler
      allowed_ref = make_ref()
      exceeded_ref = make_ref()
      test_pid = self()
      
      :telemetry.attach(
        "test-allowed-#{inspect(allowed_ref)}",
        [:rsolv, :rate_limiter, :request_allowed],
        fn _event, measurements, metadata, _config ->
          send(test_pid, {:telemetry_allowed, measurements, metadata})
        end,
        nil
      )
      
      :telemetry.attach(
        "test-exceeded-#{inspect(exceeded_ref)}",
        [:rsolv, :rate_limiter, :limit_exceeded],
        fn _event, measurements, metadata, _config ->
          send(test_pid, {:telemetry_exceeded, measurements, metadata})
        end,
        nil
      )
      
      # Make a successful request
      assert :ok = RateLimiter.check_rate_limit(customer_id, action)
      
      assert_receive {:telemetry_allowed, measurements, metadata}
      assert measurements.count == 1
      assert measurements.current_count == 1
      assert metadata.customer_id == customer_id
      assert metadata.action == action
      assert metadata.limit == 100
      
      # Use up the quota
      for _ <- 2..100 do
        RateLimiter.check_rate_limit(customer_id, action)
      end
      
      # Exceed the limit
      assert {:error, :rate_limited} = RateLimiter.check_rate_limit(customer_id, action)
      
      assert_receive {:telemetry_exceeded, measurements, metadata}
      assert measurements.count == 1
      assert metadata.customer_id == customer_id
      assert metadata.action == action
      assert metadata.current_count == 100
      assert metadata.limit == 100
      
      # Cleanup
      :telemetry.detach("test-allowed-#{inspect(allowed_ref)}")
      :telemetry.detach("test-exceeded-#{inspect(exceeded_ref)}")
    end
  end
  
  describe "reset/0" do
    test "clears all rate limit data" do
      customer_id = "reset-test-customer"
      action = "action"
      
      # Add requests up to the limit
      for _ <- 1..50 do
        RateLimiter.check_rate_limit(customer_id, action)
      end
      
      # Verify we have some count
      assert RateLimiter.get_current_count(customer_id, action) > 0
      
      # Reset
      RateLimiter.reset()
      
      # Verify data is cleared - count should be 0
      assert RateLimiter.get_current_count(customer_id, action) == 0
      
      # Verify we can make requests again
      assert :ok = RateLimiter.check_rate_limit(customer_id, action)
    end
  end
  
  describe "distributed rate limiting" do
    @tag :distributed
    test "Mnesia provides consistent rate limiting" do
      # With Mnesia, rate limiting is automatically consistent across nodes
      # This test verifies the Mnesia-based implementation works correctly
      
      customer_id = "dist-test-customer"
      action = "dist-action"
      
      # Reset to ensure clean state
      RateLimiter.reset()
      
      # Add 100 requests (the default limit)
      for _ <- 1..100 do
        assert :ok = RateLimiter.check_rate_limit(customer_id, action)
      end
      
      # The 101st request should be rate limited
      assert {:error, :rate_limited} = RateLimiter.check_rate_limit(customer_id, action)
      
      # Verify the count is correct
      assert RateLimiter.get_current_count(customer_id, action) == 100
    end
  end
end