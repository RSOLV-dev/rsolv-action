defmodule Rsolv.AST.ParserPoolTest do
  use ExUnit.Case, async: false
  
  alias Rsolv.AST.ParserPool
  
  # Helper to generate unique pool name for each test
  defp unique_pool_name do
    :"test_pool_#{System.unique_integer([:positive])}"
  end
  
  describe "pool initialization" do
    test "starts with configured pool size" do
      config = %{
        name: unique_pool_name(),
        languages: ["javascript", "python"],
        pool_size: 3,
        pre_warm: true
      }
      
      pool = start_supervised!({ParserPool, config})
      
      # Should have 3 parsers per language
      status = ParserPool.get_pool_status(pool)
      assert status["javascript"].total == 3
      assert status["python"].total == 3
      
      # Wait for parsers to warm up if pre_warm is true
      if config.pre_warm do
        assert wait_for_condition(fn ->
          status = ParserPool.get_pool_status(pool)
          status["javascript"].available == 3 && status["python"].available == 3
        end, 5000, "Parsers did not become available")
      end
    end
    
    test "pre-warms parsers on startup" do
      config = %{
        name: unique_pool_name(),
        languages: ["javascript"],
        pool_size: 2,
        pre_warm: true
      }
      
      pool = start_supervised!({ParserPool, config})
      
      # Wait for all parsers to warm up (with timeout)
      assert wait_for_parsers_warmed(pool, "javascript", 2, 5_000)
      
      # All parsers should be warmed (health check passed)
      status = ParserPool.get_parser_status(pool, "javascript")
      assert Enum.all?(status, fn {_id, info} -> info.warmed == true end)
    end
    
    test "lazy initialization when pre_warm is false" do
      config = %{
        name: unique_pool_name(),
        languages: ["javascript"],
        pool_size: 2,
        pre_warm: false
      }
      
      pool = start_supervised!({ParserPool, config})
      
      # Parsers should not be started yet
      status = ParserPool.get_pool_status(pool)
      assert status["javascript"].available == 0
    end
  end
  
  describe "parser checkout/checkin" do
    setup do
      config = %{
        name: unique_pool_name(),
        languages: ["javascript"],
        pool_size: 2,
        pre_warm: true
      }
      
      pool = start_supervised!({ParserPool, config})
      # Wait for parsers to warm up
      wait_for_parsers_warmed(pool, "javascript", 2, 5_000)
      
      {:ok, pool: pool}
    end
    
    test "checkout returns available parser", %{pool: pool} do
      {:ok, parser_id} = ParserPool.checkout(pool, "javascript")
      assert is_binary(parser_id)
      
      # Pool should show 1 available, 1 busy
      status = ParserPool.get_pool_status(pool)
      assert status["javascript"] == %{available: 1, busy: 1, total: 2}
    end
    
    test "checkin returns parser to pool", %{pool: pool} do
      {:ok, parser_id} = ParserPool.checkout(pool, "javascript")
      :ok = ParserPool.checkin(pool, "javascript", parser_id)
      
      # Pool should show all available again
      status = ParserPool.get_pool_status(pool)
      assert status["javascript"] == %{available: 2, busy: 0, total: 2}
    end
    
    test "blocks when all parsers busy", %{pool: pool} do
      # Checkout all parsers
      {:ok, p1} = ParserPool.checkout(pool, "javascript")
      {:ok, p2} = ParserPool.checkout(pool, "javascript")
      
      # Next checkout should block
      task = Task.async(fn ->
        ParserPool.checkout(pool, "javascript", timeout: 100)
      end)
      
      # Should timeout
      assert {:error, :timeout} = Task.await(task)
      
      # Return one parser
      ParserPool.checkin(pool, "javascript", p1)
      
      # Now checkout should succeed
      {:ok, _p3} = ParserPool.checkout(pool, "javascript")
    end
    
    test "handles parser crashes gracefully", %{pool: pool} do
      {:ok, parser_id} = ParserPool.checkout(pool, "javascript")
      
      # Simulate parser crash
      ParserPool.report_crash(pool, "javascript", parser_id)
      
      # Pool should spawn replacement
      assert wait_for_condition(fn ->
        status = ParserPool.get_pool_status(pool)
        status["javascript"].total == 2
      end, 2000, "Pool did not spawn replacement parser")
    end
  end
  
  describe "pool metrics" do
    setup do
      config = %{
        name: unique_pool_name(),
        languages: ["javascript", "python"],
        pool_size: 3,
        pre_warm: true,
        enable_metrics: true
      }
      
      pool = start_supervised!({ParserPool, config})
      # Wait for parsers to warm up
      wait_for_parsers_warmed(pool, "javascript", 2, 5_000)
      wait_for_parsers_warmed(pool, "python", 1, 5_000)
      
      {:ok, pool: pool}
    end
    
    test "tracks utilization metrics", %{pool: pool} do
      # Perform some checkouts
      {:ok, p1} = ParserPool.checkout(pool, "javascript", timeout: 5000)
      {:ok, p2} = ParserPool.checkout(pool, "javascript", timeout: 5000)
      # Small delay to ensure metrics are updated
      :timer.sleep(50)
      ParserPool.checkin(pool, "javascript", p1)
      
      metrics = ParserPool.get_metrics(pool)
      
      assert metrics["javascript"][:checkouts] == 2
      assert metrics["javascript"][:checkins] == 1
      assert metrics["javascript"][:utilization] > 0
      assert metrics["javascript"][:avg_wait_time_ms] >= 0
    end
    
    test "tracks parser health", %{pool: pool} do
      # Simulate some successful parses and failures
      {:ok, parser_id} = ParserPool.checkout(pool, "python")
      ParserPool.report_success(pool, "python", parser_id, parse_time_ms: 45)
      ParserPool.report_failure(pool, "python", parser_id, reason: :timeout)
      
      metrics = ParserPool.get_metrics(pool)
      
      assert metrics["python"][:successful_parses] == 1
      assert metrics["python"][:failed_parses] == 1
      assert metrics["python"][:avg_parse_time_ms] == 45
      assert metrics["python"][:health_score] < 1.0
    end
  end
  
  describe "dynamic scaling" do
    test "scales up when high demand" do
      config = %{
        name: unique_pool_name(),
        languages: ["javascript"],
        pool_size: 2,
        pre_warm: true,
        enable_autoscaling: true,
        max_pool_size: 5
      }
      
      pool = start_supervised!({ParserPool, config})
      # Wait for parsers to warm up using our helper
      assert wait_for_parsers_warmed(pool, "javascript", 2, 5_000)
      
      # Create high demand by checking out all parsers and holding them
      {:ok, p1} = ParserPool.checkout(pool, "javascript", timeout: 5000)
      {:ok, p2} = ParserPool.checkout(pool, "javascript", timeout: 5000)
      
      # Try to checkout more (should trigger scaling)
      tasks = for _ <- 1..3 do
        Task.async(fn ->
          case ParserPool.checkout(pool, "javascript", timeout: 1000) do
            {:ok, pid} -> {:ok, pid}
            {:error, :timeout} -> :timeout
          end
        end)
      end
      
      # Trigger autoscaler manually
      ParserPool.trigger_scaling(pool)
      
      # Wait for pool to scale up
      assert wait_for_condition(fn ->
        status = ParserPool.get_pool_status(pool)
        status["javascript"].total > 2
      end, 2000, "Pool did not scale up")
      
      # Verify it didn't scale beyond max
      status = ParserPool.get_pool_status(pool)
      assert status["javascript"].total <= 5
      
      # Cleanup
      ParserPool.checkin(pool, "javascript", p1)
      ParserPool.checkin(pool, "javascript", p2)
      
      # Get any successful checkouts from tasks
      results = Task.await_many(tasks, 100)
      results
      |> Enum.filter(fn 
        {:ok, _} -> true
        _ -> false
      end)
      |> Enum.each(fn {:ok, parser_id} ->
        ParserPool.checkin(pool, "javascript", parser_id)
      end)
    end
    
    test "scales down when low demand" do
      config = %{
        name: unique_pool_name(),
        languages: ["javascript"],
        pool_size: 5,
        pre_warm: true,
        enable_autoscaling: true,
        min_pool_size: 2,
        scale_down_after_ms: 100
      }
      
      pool = start_supervised!({ParserPool, config})
      # Wait for initial parsers to warm up
      wait_for_parsers_warmed(pool, "javascript", 2, 5_000)
      
      # Wait a bit for scale_down_after_ms to pass
      :timer.sleep(200)
      
      # Trigger scaling check
      ParserPool.trigger_scaling(pool)
      
      # Wait for pool to scale down
      assert wait_for_condition(fn ->
        status = ParserPool.get_pool_status(pool)
        status["javascript"].total < 5
      end, 2000, "Pool did not scale down")
      
      # Verify minimum is maintained
      status = ParserPool.get_pool_status(pool)
      assert status["javascript"].total >= 2
    end
  end
  
  # Helper function to wait for parsers to be warmed
  defp wait_for_parsers_warmed(pool, language, expected_count, timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout
    
    wait_for_parsers_warmed_loop(pool, language, expected_count, deadline)
  end
  
  defp wait_for_parsers_warmed_loop(pool, language, expected_count, deadline) do
    if System.monotonic_time(:millisecond) >= deadline do
      false
    else
      status = ParserPool.get_parser_status(pool, language)
      warmed_count = Enum.count(status, fn {_id, info} -> info.warmed == true end)
      
      if warmed_count >= expected_count do
        true
      else
        Process.sleep(50)
        wait_for_parsers_warmed_loop(pool, language, expected_count, deadline)
      end
    end
  end
  
  # Generic helper to wait for any condition
  defp wait_for_condition(condition_fn, timeout, message \\ "Condition not met") do
    deadline = System.monotonic_time(:millisecond) + timeout
    do_wait_for_condition(condition_fn, deadline, message)
  end
  
  defp do_wait_for_condition(condition_fn, deadline, message) do
    if System.monotonic_time(:millisecond) >= deadline do
      flunk(message)
    end
    
    if condition_fn.() do
      true
    else
      Process.sleep(10)
      do_wait_for_condition(condition_fn, deadline, message)
    end
  end
end