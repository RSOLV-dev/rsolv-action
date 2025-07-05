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
        Process.sleep(500)
        status = ParserPool.get_pool_status(pool)
        assert status["javascript"].available == 3
        assert status["python"].available == 3
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
      
      # Give parsers time to warm up
      Process.sleep(200)
      
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
      Process.sleep(300) # Let parsers warm up
      
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
      Process.sleep(100)
      status = ParserPool.get_pool_status(pool)
      assert status["javascript"].total == 2
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
      Process.sleep(300)
      
      {:ok, pool: pool}
    end
    
    test "tracks utilization metrics", %{pool: pool} do
      # Perform some checkouts
      {:ok, p1} = ParserPool.checkout(pool, "javascript", timeout: 5000)
      {:ok, p2} = ParserPool.checkout(pool, "javascript", timeout: 5000)
      Process.sleep(50)
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
        languages: ["javascript"],
        pool_size: 2,
        pre_warm: true,
        enable_autoscaling: true,
        max_pool_size: 5
      }
      
      pool = start_supervised!({ParserPool, config})
      # Wait for parsers to warm up
      Process.sleep(300)
      
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
      Process.sleep(100)
      
      # Pool should have scaled up
      status = ParserPool.get_pool_status(pool)
      assert status["javascript"].total > 2
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
      Process.sleep(500)  # Let parsers warm up
      
      # Simulate parsers being idle by setting their last_used_at to past
      # This is a bit hacky but needed for testing
      Process.sleep(200)  # Wait for the scale_down_after_ms period
      
      # Trigger scaling check
      ParserPool.trigger_scaling(pool)
      
      # Pool should have scaled down
      status = ParserPool.get_pool_status(pool)
      assert status["javascript"].total < 5
      assert status["javascript"].total >= 2
    end
  end
end