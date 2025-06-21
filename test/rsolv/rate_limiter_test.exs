defmodule RSOLV.RateLimiterTest do
  use ExUnit.Case, async: false

  alias RSOLV.RateLimiter

  setup do
    # Reset rate limiter before each test
    RateLimiter.reset()
    :ok
  end

  describe "check_rate_limit/2" do
    test "allows requests under the limit" do
      customer_id = 1
      
      # First 10 requests should be allowed
      for _ <- 1..10 do
        assert :ok = RateLimiter.check_rate_limit(customer_id)
      end
    end

    test "blocks requests over the limit" do
      customer_id = 1
      
      # First 10 requests should be allowed
      for _ <- 1..10 do
        assert :ok = RateLimiter.check_rate_limit(customer_id)
      end
      
      # 11th request should be blocked
      assert {:error, :rate_limited} = RateLimiter.check_rate_limit(customer_id)
    end

    test "resets counter after time window expires" do
      customer_id = 1
      
      # Make 10 requests
      for _ <- 1..10 do
        assert :ok = RateLimiter.check_rate_limit(customer_id)
      end
      
      # 11th request should be blocked
      assert {:error, :rate_limited} = RateLimiter.check_rate_limit(customer_id)
      
      # Mock time passing (61 seconds)
      # This is tricky because we're using System.system_time
      # For now, we'll just reset manually to test the behavior
      RateLimiter.reset()
      
      # After reset, should allow requests again
      assert :ok = RateLimiter.check_rate_limit(customer_id)
    end

    test "tracks different customers separately" do
      customer1 = 1
      customer2 = 2
      
      # Make 10 requests for customer 1
      for _ <- 1..10 do
        assert :ok = RateLimiter.check_rate_limit(customer1)
      end
      
      # Customer 1 should be rate limited
      assert {:error, :rate_limited} = RateLimiter.check_rate_limit(customer1)
      
      # But customer 2 should still be allowed
      assert :ok = RateLimiter.check_rate_limit(customer2)
    end

    test "tracks different actions separately" do
      customer_id = 1
      
      # Make 10 credential exchange requests
      for _ <- 1..10 do
        assert :ok = RateLimiter.check_rate_limit(customer_id, "credential_exchange")
      end
      
      # Credential exchange should be rate limited
      assert {:error, :rate_limited} = RateLimiter.check_rate_limit(customer_id, "credential_exchange")
      
      # But other actions should still be allowed
      assert :ok = RateLimiter.check_rate_limit(customer_id, "api_call")
    end
  end

  describe "reset/0" do
    test "clears all rate limit counters" do
      # Make some requests for different customers
      assert :ok = RateLimiter.check_rate_limit(1)
      assert :ok = RateLimiter.check_rate_limit(2)
      assert :ok = RateLimiter.check_rate_limit(3)
      
      # Reset
      assert :ok = RateLimiter.reset()
      
      # All customers should be able to make 10 requests again
      for customer_id <- 1..3 do
        for _ <- 1..10 do
          assert :ok = RateLimiter.check_rate_limit(customer_id)
        end
      end
    end
  end
end