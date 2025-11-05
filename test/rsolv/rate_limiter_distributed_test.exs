defmodule Rsolv.RateLimiterDistributedTest do
  use ExUnit.Case, async: false

  # Skip distributed tests - require LocalCluster setup
  @moduletag :skip

  # Use LocalCluster library for cleaner distributed testing

  setup do
    # Start the current node as distributed
    :net_kernel.start([:"primary@127.0.0.1"])

    # Start cluster with 2 additional nodes
    nodes = LocalCluster.start_nodes("test", 2)

    # Start rate limiter on all nodes
    for node <- nodes do
      :rpc.call(node, Rsolv.RateLimiter, :start_link, [[]])
    end

    on_exit(fn ->
      LocalCluster.stop()
    end)

    {:ok, %{nodes: nodes}}
  end

  describe "distributed rate limiting" do
    test "rate limits are shared across nodes", %{nodes: [node1, node2]} do
      # Clear rate limiter on all nodes
      :rpc.call(node1, Rsolv.RateLimiter, :reset, [])
      :rpc.call(node2, Rsolv.RateLimiter, :reset, [])

      # Make 50 requests from first node
      for i <- 1..50 do
        result =
          :rpc.call(node1, Rsolv.RateLimiter, :check_rate_limit, ["shared_customer", :test_action])

        assert result == :ok, "Request #{i} from node1 should be allowed"
      end

      # Make 50 more requests from second node - should continue counting
      for i <- 51..100 do
        result =
          :rpc.call(node2, Rsolv.RateLimiter, :check_rate_limit, ["shared_customer", :test_action])

        assert result == :ok, "Request #{i} from node2 should be allowed"
      end

      # 101st request from either node should be denied
      result1 =
        :rpc.call(node1, Rsolv.RateLimiter, :check_rate_limit, ["shared_customer", :test_action])

      assert result1 == {:error, :rate_limited}, "101st request from node1 should be denied"

      result2 =
        :rpc.call(node2, Rsolv.RateLimiter, :check_rate_limit, ["shared_customer", :test_action])

      assert result2 == {:error, :rate_limited}, "101st request from node2 should be denied"
    end

    test "new nodes get existing rate limit data", %{nodes: nodes} do
      [node1, _node2] = nodes

      # Clear rate limiter
      :rpc.call(node1, Rsolv.RateLimiter, :reset, [])

      # Create rate limit data on first node
      for i <- 1..50 do
        result =
          :rpc.call(node1, Rsolv.RateLimiter, :check_rate_limit, ["test_customer", :test_action])

        assert result == :ok, "Request #{i} should be allowed"
      end

      # Start a third node dynamically
      [node3] = LocalCluster.start_nodes("test", 1)
      :rpc.call(node3, Rsolv.RateLimiter, :start_link, [[]])

      # Wait for Mnesia table to sync (using proper table wait instead of fixed sleep)
      assert :ok = :rpc.call(node3, :mnesia, :wait_for_tables, [[:rsolv_rate_limiter], 5000])

      # Node3 should continue counting from where we left off
      for i <- 51..100 do
        result =
          :rpc.call(node3, Rsolv.RateLimiter, :check_rate_limit, ["test_customer", :test_action])

        assert result == :ok, "Request #{i} from node3 should be allowed"
      end

      # Next request should be denied
      result =
        :rpc.call(node3, Rsolv.RateLimiter, :check_rate_limit, ["test_customer", :test_action])

      assert result == {:error, :rate_limited}, "101st request should be denied"

      # Clean up the extra node
      LocalCluster.stop_member(node3)
    end

    test "survives node failure", %{nodes: [node1, node2]} do
      # Clear rate limiter
      :rpc.call(node1, Rsolv.RateLimiter, :reset, [])
      :rpc.call(node2, Rsolv.RateLimiter, :reset, [])

      # Create data on both nodes
      for i <- 1..30 do
        node = if rem(i, 2) == 0, do: node1, else: node2
        result = :rpc.call(node, Rsolv.RateLimiter, :check_rate_limit, ["survivor", :test_action])
        assert result == :ok, "Request #{i} should be allowed"
      end

      # Stop second node
      LocalCluster.stop_member(node2)

      # First node should still have the data and continue counting
      for i <- 31..100 do
        result =
          :rpc.call(node1, Rsolv.RateLimiter, :check_rate_limit, ["survivor", :test_action])

        assert result == :ok, "Request #{i} should be allowed after node2 failure"
      end

      # Next request should be denied
      result = :rpc.call(node1, Rsolv.RateLimiter, :check_rate_limit, ["survivor", :test_action])
      assert result == {:error, :rate_limited}, "101st request should be denied"
    end
  end

  describe "race conditions" do
    test "handles concurrent requests without race conditions", %{nodes: nodes} do
      # Clear rate limiter on all nodes
      for node <- nodes do
        :rpc.call(node, Rsolv.RateLimiter, :reset, [])
      end

      # Make many concurrent requests from multiple nodes
      tasks =
        for _i <- 1..100, node <- nodes do
          Task.async(fn ->
            :rpc.call(node, Rsolv.RateLimiter, :check_rate_limit, [
              "concurrent_customer",
              :test_action
            ])
          end)
        end

      results = Task.await_many(tasks, 5000)

      # Count successful and denied requests
      allowed = Enum.count(results, &(&1 == :ok))
      denied = Enum.count(results, &(&1 == {:error, :rate_limited}))

      # Should have exactly 100 allowed and the rest denied
      assert allowed == 100, "Should have exactly 100 allowed requests, got #{allowed}"
      assert denied == 100, "Should have exactly 100 denied requests, got #{denied}"
    end
  end
end
