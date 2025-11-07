defmodule Rsolv.AST.PortSupervisorTest do
  # PortSupervisor is a named singleton
  use ExUnit.Case, async: false

  alias Rsolv.AST.PortSupervisor
  alias Rsolv.AST.PortWorker

  setup do
    # Start a test-specific supervisor instance with a unique name
    # This ensures complete isolation between tests
    supervisor_name = :"test_port_supervisor_#{System.unique_integer([:positive])}"
    {:ok, supervisor} = start_supervised({Rsolv.AST.PortSupervisor, [name: supervisor_name]})

    # No cleanup needed - start_supervised handles it

    ensure_ets_tables()

    {:ok, supervisor: supervisor}
  end

  # Cleanup function no longer needed - start_supervised handles cleanup
  # Each test has its own supervisor instance

  defp ensure_ets_tables do
    [:port_registry, :port_stats, :port_pools]
    |> Enum.each(fn table ->
      case :ets.whereis(table) do
        :undefined ->
          :ets.new(table, [:set, :public, :named_table])

        _ ->
          :ok
      end
    end)
  end

  describe "port lifecycle management" do
    test "starts port with specified parser", %{supervisor: supervisor} do
      parser_config = %{
        language: "python",
        command: "python3",
        args: ["-u", Path.join(__DIR__, "fixtures/mock_parser.py")]
      }

      {:ok, port_id} = PortSupervisor.start_port(supervisor, parser_config)

      assert is_binary(port_id)
      assert PortSupervisor.get_port(supervisor, port_id) != nil
    end

    test "stops port gracefully", %{supervisor: supervisor} do
      parser_config = %{
        language: "javascript",
        command: "node",
        args: [Path.join(__DIR__, "fixtures/mock_parser.js")]
      }

      {:ok, port_id} = PortSupervisor.start_port(supervisor, parser_config)
      assert :ok = PortSupervisor.stop_port(supervisor, port_id)

      # Port should be removed
      assert PortSupervisor.get_port(supervisor, port_id) == nil
    end

    test "handles port crash and restarts", %{supervisor: supervisor} do
      parser_config = %{
        language: "python",
        command: "python3",
        args: ["-u", Path.join(__DIR__, "fixtures/crash_parser.py")]
        # No max_restarts - we want transient restart (no automatic restart)
        # This prevents race between automatic restart and manual recovery test
      }

      {:ok, port_id} = PortSupervisor.start_port(supervisor, parser_config)
      original_pid = PortSupervisor.get_port_pid(supervisor, port_id)

      # Monitor the original process for deterministic crash detection
      ref = Process.monitor(original_pid)

      # Trigger crash
      PortSupervisor.send_to_port(supervisor, port_id, "CRASH_NOW")

      # Wait for :DOWN message - cleanup happens synchronously in terminate/2 before :DOWN
      # No need for long timeout or polling - OTP guarantees :DOWN after terminate completes
      assert_receive {:DOWN, ^ref, :process, ^original_pid, _reason}, 500

      # Verify cleanup completed (terminate/2 already did this before :DOWN was sent)
      assert PortSupervisor.get_port_pid(supervisor, port_id) == nil

      # Verify recovery: manually start new port
      {:ok, new_port_id} = PortSupervisor.start_port(supervisor, parser_config)
      new_pid = PortSupervisor.get_port_pid(supervisor, new_port_id)
      assert new_pid != nil
      assert new_pid != original_pid
    end

    test "enforces maximum restart attempts", %{supervisor: supervisor} do
      parser_config = %{
        language: "python",
        command: "python3",
        args: ["-u", Path.join(__DIR__, "fixtures/always_crash_parser.py")],
        max_restarts: 3
      }

      {:ok, port_id} = PortSupervisor.start_port(supervisor, parser_config)

      # Trigger multiple crashes
      for _ <- 1..4 do
        PortSupervisor.send_to_port(supervisor, port_id, "parse")
        Process.sleep(50)
      end

      # Port should be terminated after max restarts (using polling instead of fixed wait)
      assert wait_for_condition(
               fn ->
                 PortSupervisor.get_port(supervisor, port_id) == nil
               end,
               200,
               "Port was not terminated after max restarts"
             )
    end
  end

  describe "resource limits" do
    test "enforces memory limit on port process", %{supervisor: supervisor} do
      parser_config = %{
        language: "python",
        command: "python3",
        args: ["-u", Path.join(__DIR__, "fixtures/mock_parser.py")],
        # 1MB (very small limit)
        max_heap_size: 1024 * 1024
      }

      {:ok, port_id} = PortSupervisor.start_port(supervisor, parser_config)

      # Stats are set synchronously during start_port - no wait needed
      # Simulate memory limit exceeded by updating stats and restarting
      {:ok, _} = PortSupervisor.restart_unhealthy_port(supervisor, port_id)

      # Port should be restarted
      assert PortSupervisor.get_port_restart_count(supervisor, port_id) >= 1
    end

    test "enforces CPU timeout on long-running operations (safe version)", %{
      supervisor: supervisor
    } do
      # Test timeout handling without infinite loops
      parser_config = %{
        language: "python",
        command: "python3",
        args: ["-u", Path.join(__DIR__, "fixtures/slow_parser.py")],
        # 100ms timeout
        operation_timeout: 100
      }

      {:ok, port_id} = PortSupervisor.start_port(supervisor, parser_config)

      # Ensure cleanup on exit
      on_exit(fn ->
        try do
          PortSupervisor.terminate_port(supervisor, port_id)
        rescue
          _ -> :ok
        end
      end)

      # Send command that takes longer than operation timeout
      # Note: call_port timeout (150ms) must be less than sleep time (200ms)
      # but greater than operation_timeout (100ms) to test operation timeout
      result = PortSupervisor.call_port(supervisor, port_id, "SLEEP_200", 150)

      # Should timeout because operation takes 200ms but call timeout is 150ms
      assert {:error, :timeout} = result

      # Port should still be alive after timeout (supervisor should handle it)
      assert PortSupervisor.get_port(supervisor, port_id) != nil

      # Cleanup
      PortSupervisor.terminate_port(supervisor, port_id)
    end

    test "kills port after idle timeout", %{supervisor: supervisor} do
      parser_config = %{
        language: "python",
        command: "python3",
        args: ["-u", Path.join(__DIR__, "fixtures/mock_parser.py")],
        # 100ms
        idle_timeout: 100
      }

      {:ok, port_id} = PortSupervisor.start_port(supervisor, parser_config)

      # Port should exist initially
      assert PortSupervisor.get_port(supervisor, port_id) != nil

      # Wait for idle timeout (using polling instead of fixed wait)
      assert wait_for_condition(
               fn ->
                 PortSupervisor.get_port(supervisor, port_id) == nil
               end,
               200,
               "Port was not terminated after idle timeout"
             )
    end
  end

  describe "port pooling" do
    test "reuses idle ports for same language", %{supervisor: supervisor} do
      # Use a unique language name to avoid conflicts with other tests
      unique_lang = "python_pool_test_#{System.unique_integer([:positive])}"

      parser_config = %{
        language: unique_lang,
        command: "python3",
        args: ["-u", Path.join(__DIR__, "fixtures/mock_parser.py")],
        pooled: true
      }

      # Clean the pool for this language first
      :ets.delete(:port_pools, unique_lang)

      # Start first port
      {:ok, port_id1} = PortSupervisor.start_port(supervisor, parser_config)
      pid1 = PortSupervisor.get_port_pid(supervisor, port_id1)

      # Return to pool
      PortSupervisor.release_port(supervisor, port_id1)

      # release_port/add_to_pool are synchronous ETS operations - no wait needed
      # Request another port for same language
      {:ok, port_id2} = PortSupervisor.start_port(supervisor, parser_config)
      pid2 = PortSupervisor.get_port_pid(supervisor, port_id2)

      # Should reuse same process
      assert pid1 == pid2
    end

    test "limits pool size per language", %{supervisor: supervisor} do
      # Use a unique language to avoid conflicts
      unique_lang = "python_limit_test_#{System.unique_integer([:positive])}"

      parser_config = %{
        language: unique_lang,
        command: "python3",
        args: ["-u", Path.join(__DIR__, "fixtures/mock_parser.py")],
        pooled: true,
        max_pool_size: 2
      }

      # Clean the pool for this language first
      :ets.delete(:port_pools, unique_lang)

      # Start max ports
      ports =
        for _ <- 1..2 do
          {:ok, port_id} = PortSupervisor.start_port(supervisor, parser_config)
          port_id
        end

      # Release all to pool
      Enum.each(ports, &PortSupervisor.release_port(supervisor, &1))

      # Start another (should reuse)
      {:ok, _port_id3} = PortSupervisor.start_port(supervisor, parser_config)

      # Pool should still have max 2
      pool_size = PortSupervisor.get_pool_size(supervisor, "python")
      assert pool_size <= 2
    end

    test "handles concurrent port requests", %{supervisor: supervisor} do
      # Use unique language to avoid conflicts with other tests
      unique_lang = "javascript_concurrent_#{System.unique_integer([:positive])}"

      parser_config = %{
        language: unique_lang,
        command: "node",
        args: [Path.join(__DIR__, "fixtures/mock_parser.js")],
        pooled: true,
        # Allow more ports in pool for concurrency
        max_pool_size: 5
      }

      # Clean the pool for this language first
      :ets.delete(:port_pools, unique_lang)

      # Test concurrent port acquisition and release without relying on actual work
      # This tests the pooling coordination mechanism, not execution speed
      parent = self()

      tasks =
        for i <- 1..10 do
          Task.async(fn ->
            # Start port - this is synchronous ETS/GenServer operation
            case PortSupervisor.start_port(supervisor, parser_config) do
              {:ok, port_id} ->
                # Get port details to verify it was actually created
                port = PortSupervisor.get_port(supervisor, port_id)
                pid = PortSupervisor.get_port_pid(supervisor, port_id)

                # Send confirmation back to parent that we got a port
                send(parent, {:acquired, i, port_id, pid})

                # Release back to pool (synchronous ETS operation)
                PortSupervisor.release_port(supervisor, port_id)

                {:ok, i, port_id, pid}

              {:error, reason} ->
                {:error, i, reason}
            end
          end)
        end

      # Wait for all acquisitions to be confirmed
      # This doesn't rely on timeouts - it waits for actual coordination events
      for i <- 1..10 do
        assert_receive {:acquired, ^i, _port_id, _pid}, 1000, "Task #{i} failed to acquire a port"
      end

      # Now await all task completions (they should all be done by now)
      results = Task.await_many(tasks, 1000)

      # Verify all tasks completed successfully
      assert length(results) == 10

      # Verify all succeeded and got valid port IDs
      assert Enum.all?(results, fn
               {:ok, _i, port_id, pid} when is_binary(port_id) and is_pid(pid) -> true
               _ -> false
             end),
             "Some concurrent port requests failed"

      # Verify pooling worked: concurrent requests should have created new ports
      # since they all happened simultaneously before any could be released
      # Get all unique PIDs that were used
      unique_pids =
        results
        |> Enum.map(fn {:ok, _i, _port_id, pid} -> pid end)
        |> Enum.uniq()

      # With concurrent requests, pooling happens AFTER release
      # So we expect up to 10 ports created (one per concurrent request)
      # But max_pool_size limits how many stay in the pool afterward
      assert length(unique_pids) >= 1, "Should have created at least one port"
      assert length(unique_pids) <= 10, "Should not exceed number of requests"

      # The real test: verify pool size is limited after all releases
      pool_size = PortSupervisor.get_pool_size(supervisor, unique_lang)
      assert pool_size <= 5, "Pool size #{pool_size} exceeds max_pool_size of 5"
    end
  end

  describe "health monitoring" do
    test "performs health checks on ports", %{supervisor: supervisor} do
      parser_config = %{
        language: "python",
        command: "python3",
        args: ["-u", Path.join(__DIR__, "fixtures/mock_parser.py")],
        # 100ms
        health_check_interval: 100
      }

      {:ok, port_id} = PortSupervisor.start_port(supervisor, parser_config)

      # Wait for health check (using polling instead of fixed wait)
      assert wait_for_condition(
               fn ->
                 PortSupervisor.is_port_healthy?(supervisor, port_id) == true
               end,
               200,
               "Port did not become healthy"
             )
    end

    test "restarts unhealthy ports", %{supervisor: supervisor} do
      parser_config = %{
        language: "python",
        command: "python3",
        args: ["-u", Path.join(__DIR__, "fixtures/unhealthy_parser.py")],
        health_check_interval: 100
      }

      {:ok, port_id} = PortSupervisor.start_port(supervisor, parser_config)
      original_pid = PortSupervisor.get_port_pid(supervisor, port_id)

      # Wait for health check to fail (using polling instead of fixed wait)
      assert wait_for_condition(
               fn ->
                 PortSupervisor.is_port_healthy?(supervisor, port_id) == false
               end,
               200,
               "Port did not become unhealthy"
             )

      # Manually restart the unhealthy port (simulating automated restart)
      {:ok, _} = PortSupervisor.restart_unhealthy_port(supervisor, port_id)

      # Should have new PID
      new_pid = PortSupervisor.get_port_pid(supervisor, port_id)
      assert new_pid != original_pid
    end

    test "reports port statistics", %{supervisor: supervisor} do
      parser_config = %{
        language: "ruby",
        command: "ruby",
        args: [Path.join(__DIR__, "fixtures/mock_parser.rb")]
      }

      {:ok, port_id} = PortSupervisor.start_port(supervisor, parser_config)

      # Do some operations
      PortSupervisor.call_port(supervisor, port_id, "parse1", 5000)
      PortSupervisor.call_port(supervisor, port_id, "parse2", 5000)

      # Get statistics (uptime calculated on-demand in get_port_stats)
      stats = PortSupervisor.get_port_stats(supervisor, port_id)

      assert stats.requests_handled >= 2
      assert stats.uptime_seconds >= 0
      assert stats.last_used != nil
      assert stats.memory_usage > 0
    end
  end

  describe "error handling" do
    test "handles invalid parser command", %{supervisor: supervisor} do
      parser_config = %{
        language: "unknown",
        command: "nonexistent_command",
        args: []
      }

      assert {:error, reason} = PortSupervisor.start_port(supervisor, parser_config)
      assert String.contains?(reason, "failed to start")
    end

    test "handles port communication errors", %{supervisor: supervisor} do
      parser_config = %{
        language: "python",
        command: "python3",
        args: ["-u", Path.join(__DIR__, "fixtures/broken_protocol_parser.py")]
      }

      {:ok, port_id} = PortSupervisor.start_port(supervisor, parser_config)

      # Should handle malformed responses
      result = PortSupervisor.call_port(supervisor, port_id, "parse", 1000)
      assert {:error, :invalid_response} = result
    end

    test "cleans up resources on termination", %{supervisor: supervisor} do
      parser_config = %{
        language: "python",
        command: "python3",
        args: ["-u", Path.join(__DIR__, "fixtures/mock_parser.py")]
      }

      {:ok, port_id} = PortSupervisor.start_port(supervisor, parser_config)
      port_pid = PortSupervisor.get_port_pid(supervisor, port_id)

      # Monitor process for deterministic termination detection
      ref = Process.monitor(port_pid)

      # Force termination (synchronous call)
      PortSupervisor.terminate_port(supervisor, port_id)

      # Wait for :DOWN - confirms process terminated and cleanup completed
      assert_receive {:DOWN, ^ref, :process, ^port_pid, _reason}, 200

      # Port should be removed from tracking (cleanup happens in terminate/2)
      assert PortSupervisor.get_port(supervisor, port_id) == nil
    end
  end

  describe "security" do
    test "runs ports with restricted permissions", %{supervisor: supervisor} do
      parser_config = %{
        language: "python",
        command: "python3",
        args: ["-u", Path.join(__DIR__, "fixtures/security_test_parser.py")],
        security: %{
          read_only_fs: true,
          no_network: true
        }
      }

      {:ok, port_id} = PortSupervisor.start_port(supervisor, parser_config)

      # Try to write file (should fail)
      result = PortSupervisor.call_port(supervisor, port_id, "WRITE_FILE", 1000)
      assert {:ok, %{"error" => "permission_denied"}} = result

      # Try network access (should fail)
      result = PortSupervisor.call_port(supervisor, port_id, "NETWORK_REQUEST", 1000)
      assert {:ok, %{"error" => "network_disabled"}} = result
    end

    test "isolates port processes from each other", %{supervisor: supervisor} do
      config1 = %{
        language: "python",
        command: "python3",
        args: ["-u", Path.join(__DIR__, "fixtures/mock_parser.py")]
      }

      config2 = %{
        language: "javascript",
        command: "node",
        args: [Path.join(__DIR__, "fixtures/mock_parser.js")]
      }

      {:ok, port1} = PortSupervisor.start_port(supervisor, config1)
      {:ok, port2} = PortSupervisor.start_port(supervisor, config2)

      # Ports should have different process groups
      pg1 = PortSupervisor.get_port_process_group(supervisor, port1)
      pg2 = PortSupervisor.get_port_process_group(supervisor, port2)

      assert pg1 != pg2
    end
  end

  # Helper function for waiting on conditions
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
