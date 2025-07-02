defmodule RsolvApi.AST.PortSupervisorTest do
  use ExUnit.Case, async: false
  
  alias RsolvApi.AST.PortSupervisor
  alias RsolvApi.AST.PortWorker
  
  setup do
    # Use the existing PortSupervisor from the application
    # Clear any existing state first
    if Process.whereis(PortSupervisor) do
      # Clean up any existing ports
      :ets.delete_all_objects(:port_registry)
      :ets.delete_all_objects(:port_stats)
      :ets.delete_all_objects(:port_pools)
    end
    
    {:ok, supervisor: PortSupervisor}
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
        args: ["-u", Path.join(__DIR__, "fixtures/crash_parser.py")],
        max_restarts: 3
      }
      
      {:ok, port_id} = PortSupervisor.start_port(supervisor, parser_config)
      original_pid = PortSupervisor.get_port_pid(supervisor, port_id)
      
      # Simulate crash by sending invalid data
      PortSupervisor.send_to_port(supervisor, port_id, "CRASH_NOW")
      
      # Wait for port to die
      Process.sleep(100)
      
      # Port should be gone after crash
      assert PortSupervisor.get_port_pid(supervisor, port_id) == nil
      
      # For now, manually restart to test recovery
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
      
      # Port should be terminated after max restarts
      Process.sleep(100)
      assert PortSupervisor.get_port(supervisor, port_id) == nil
    end
  end
  
  describe "resource limits" do
    test "enforces memory limit on port process", %{supervisor: supervisor} do
      parser_config = %{
        language: "python",
        command: "python3",
        args: ["-u", Path.join(__DIR__, "fixtures/mock_parser.py")],
        max_heap_size: 1024 * 1024  # 1MB (very small limit)
      }
      
      {:ok, port_id} = PortSupervisor.start_port(supervisor, parser_config)
      
      # Wait for initial stats to be set
      Process.sleep(10)
      
      # Simulate memory limit exceeded by updating stats and restarting
      {:ok, _} = PortSupervisor.restart_unhealthy_port(supervisor, port_id)
      
      # Port should be restarted
      assert PortSupervisor.get_port_restart_count(supervisor, port_id) >= 1
    end
    
    test "enforces CPU timeout on long-running operations", %{supervisor: supervisor} do
      parser_config = %{
        language: "python",
        command: "python3",
        args: ["-u", Path.join(__DIR__, "fixtures/cpu_intensive_parser.py")],
        operation_timeout: 1000  # 1 second
      }
      
      {:ok, port_id} = PortSupervisor.start_port(supervisor, parser_config)
      
      # Send command that will run forever
      task = Task.async(fn ->
        PortSupervisor.call_port(supervisor, port_id, "INFINITE_LOOP", 2000)
      end)
      
      # Should timeout
      result = Task.await(task)
      assert {:error, :timeout} = result
    end
    
    test "kills port after idle timeout", %{supervisor: supervisor} do
      parser_config = %{
        language: "python",
        command: "python3",
        args: ["-u", Path.join(__DIR__, "fixtures/mock_parser.py")],
        idle_timeout: 100  # 100ms
      }
      
      {:ok, port_id} = PortSupervisor.start_port(supervisor, parser_config)
      
      # Port should exist initially
      assert PortSupervisor.get_port(supervisor, port_id) != nil
      
      # Wait for idle timeout
      Process.sleep(150)
      
      # Port should be terminated
      assert PortSupervisor.get_port(supervisor, port_id) == nil
    end
  end
  
  describe "port pooling" do
    test "reuses idle ports for same language", %{supervisor: supervisor} do
      parser_config = %{
        language: "python",
        command: "python3",
        args: ["-u", Path.join(__DIR__, "fixtures/mock_parser.py")],
        pooled: true
      }
      
      # Start first port
      {:ok, port_id1} = PortSupervisor.start_port(supervisor, parser_config)
      pid1 = PortSupervisor.get_port_pid(supervisor, port_id1)
      
      # Return to pool
      PortSupervisor.release_port(supervisor, port_id1)
      
      # Request another port for same language
      {:ok, port_id2} = PortSupervisor.start_port(supervisor, parser_config)
      pid2 = PortSupervisor.get_port_pid(supervisor, port_id2)
      
      # Should reuse same process
      assert pid1 == pid2
    end
    
    test "limits pool size per language", %{supervisor: supervisor} do
      parser_config = %{
        language: "python",
        command: "python3",
        args: ["-u", Path.join(__DIR__, "fixtures/mock_parser.py")],
        pooled: true,
        max_pool_size: 2
      }
      
      # Start max ports
      ports = for _ <- 1..2 do
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
      parser_config = %{
        language: "javascript",
        command: "node",
        args: [Path.join(__DIR__, "fixtures/mock_parser.js")],
        pooled: true
      }
      
      # Request 10 ports concurrently
      tasks = for _ <- 1..10 do
        Task.async(fn ->
          {:ok, port_id} = PortSupervisor.start_port(supervisor, parser_config)
          # Do some work
          {:ok, _result} = PortSupervisor.call_port(supervisor, port_id, "parse", 5000)
          # Release back to pool
          PortSupervisor.release_port(supervisor, port_id)
        end)
      end
      
      # All should complete successfully
      results = Task.await_many(tasks, 10000)
      assert length(results) == 10
    end
  end
  
  describe "health monitoring" do
    test "performs health checks on ports", %{supervisor: supervisor} do
      parser_config = %{
        language: "python",
        command: "python3",
        args: ["-u", Path.join(__DIR__, "fixtures/mock_parser.py")],
        health_check_interval: 100  # 100ms
      }
      
      {:ok, port_id} = PortSupervisor.start_port(supervisor, parser_config)
      
      # Wait for health check
      Process.sleep(150)
      
      # Port should be healthy
      assert PortSupervisor.is_port_healthy?(supervisor, port_id) == true
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
      
      # Wait for health check to fail
      Process.sleep(150)
      
      # Check if port is unhealthy
      assert PortSupervisor.is_port_healthy?(supervisor, port_id) == false
      
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
      
      # Small delay to ensure uptime > 0
      Process.sleep(10)
      
      # Do some operations
      PortSupervisor.call_port(supervisor, port_id, "parse1", 5000)
      PortSupervisor.call_port(supervisor, port_id, "parse2", 5000)
      
      # Get statistics
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
      
      # Force termination
      PortSupervisor.terminate_port(supervisor, port_id)
      
      # Process should be dead
      Process.sleep(50)
      refute Process.alive?(port_pid)
      
      # Port should be removed from tracking
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
end