defmodule Rsolv.AST.PortCleanupTest do
  use ExUnit.Case, async: false
  
  alias Rsolv.AST.PortSupervisor
  
  setup do
    # Start the supervisor if not already started
    case GenServer.whereis(PortSupervisor) do
      nil -> start_supervised!(PortSupervisor)
      _ -> :ok
    end
    
    :ok
  end
  
  describe "process cleanup" do
    test "kills CPU-intensive processes when port is terminated" do
      # Start a CPU-intensive parser
      config = %{
        language: "test",
        command: "python3",
        args: ["-u", Path.join([__DIR__, "fixtures", "cpu_intensive_parser.py"])],
        timeout: 5000
      }
      
      {:ok, port_id} = PortSupervisor.start_port(PortSupervisor, config)
      
      # Get the OS PID before triggering infinite loop
      port_info = PortSupervisor.get_port(PortSupervisor, port_id)
      state = :sys.get_state(port_info.pid)
      {:os_pid, os_pid} = Port.info(state.port, :os_pid)
      
      # Verify process is running
      {output, 0} = System.cmd("ps", ["-p", "#{os_pid}"])
      assert output =~ to_string(os_pid)
      
      # Trigger infinite loop in a task so we don't block
      task = Task.async(fn ->
        try do
          PortSupervisor.call_port(PortSupervisor, port_id, "INFINITE_LOOP", 1000)
        catch
          :exit, _ -> :ok
        end
      end)
      
      # Give it a moment to start the infinite loop
      Process.sleep(200)
      
      # Kill the port
      PortSupervisor.stop_port(PortSupervisor, port_id)
      
      # Wait for cleanup
      Process.sleep(500)
      
      # Verify process is gone
      {output, _exit_code} = System.cmd("ps", ["-p", "#{os_pid}"], stderr_to_stdout: true)
      refute output =~ to_string(os_pid)
      
      # Clean up the task
      Task.shutdown(task, :brutal_kill)
    end
    
    test "cleans up processes on supervisor shutdown" do
      # Start a new supervisor for this test
      {:ok, sup} = DynamicSupervisor.start_link(strategy: :one_for_one)
      
      # Start multiple parsers
      configs = [
        %{
          language: "js",
          command: "python3",
          args: ["-u", Path.join([__DIR__, "fixtures", "simple_js_parser.py"])],
          timeout: 5000
        },
        %{
          language: "py",
          command: "python3",
          args: ["-u", Path.join([__DIR__, "fixtures", "simple_py_parser.py"])],
          timeout: 5000
        }
      ]
      
      port_ids = Enum.map(configs, fn config ->
        {:ok, port_id} = PortSupervisor.start_port(sup, config)
        port_id
      end)
      
      # Collect OS PIDs
      os_pids = Enum.map(port_ids, fn port_id ->
        port_info = PortSupervisor.get_port(sup, port_id)
        state = :sys.get_state(port_info.pid)
        {:os_pid, os_pid} = Port.info(state.port, :os_pid)
        os_pid
      end)
      
      # Verify all processes are running
      Enum.each(os_pids, fn os_pid ->
        {output, 0} = System.cmd("ps", ["-p", "#{os_pid}"])
        assert output =~ to_string(os_pid)
      end)
      
      # Stop the supervisor
      GenServer.stop(sup)
      
      # Wait for cleanup
      Process.sleep(500)
      
      # Verify all processes are gone
      Enum.each(os_pids, fn os_pid ->
        {output, _} = System.cmd("ps", ["-p", "#{os_pid}"], stderr_to_stdout: true)
        refute output =~ to_string(os_pid)
      end)
    end
    
    test "handles process that ignores SIGTERM" do
      # Create a test script that ignores SIGTERM
      script_content = """
      #!/usr/bin/env python3
      import signal
      import sys
      import json
      
      # Ignore SIGTERM
      signal.signal(signal.SIGTERM, signal.SIG_IGN)
      
      while True:
          line = sys.stdin.readline()
          if not line:
              break
          
          request = json.loads(line.strip())
          if request.get("command") == "INFINITE_LOOP":
              while True:
                  pass
          else:
              response = {"id": request.get("id"), "result": "ok"}
              print(json.dumps(response))
              sys.stdout.flush()
      """
      
      # Write the script to a temporary file
      script_path = Path.join(System.tmp_dir!(), "ignore_sigterm_parser.py")
      File.write!(script_path, script_content)
      File.chmod!(script_path, 0o755)
      
      config = %{
        language: "test",
        command: "python3",
        args: ["-u", script_path],
        timeout: 5000
      }
      
      {:ok, port_id} = PortSupervisor.start_port(PortSupervisor, config)
      
      # Get the OS PID
      port_info = PortSupervisor.get_port(PortSupervisor, port_id)
      state = :sys.get_state(port_info.pid)
      {:os_pid, os_pid} = Port.info(state.port, :os_pid)
      
      # Trigger infinite loop
      task = Task.async(fn ->
        try do
          PortSupervisor.call_port(PortSupervisor, port_id, "INFINITE_LOOP", 1000)
        catch
          :exit, _ -> :ok
        end
      end)
      
      # Give it a moment to start
      Process.sleep(200)
      
      # Kill the port
      PortSupervisor.stop_port(PortSupervisor, port_id)
      
      # Wait for cleanup (SIGKILL should work even if SIGTERM is ignored)
      Process.sleep(500)
      
      # Verify process is gone
      {output, _} = System.cmd("ps", ["-p", "#{os_pid}"], stderr_to_stdout: true)
      refute output =~ to_string(os_pid)
      
      # Clean up
      Task.shutdown(task, :brutal_kill)
      File.rm!(script_path)
    end
  end
  
  describe "resource usage prevention" do
    test "prevents zombie processes from accumulating" do
      # Get initial Python process count
      {initial_output, _exit_code} = System.cmd("pgrep", ["-c", "python3"], stderr_to_stdout: true)
      initial_count = case Integer.parse(String.trim(initial_output)) do
        {num, _} -> num
        :error -> 0
      end
      
      # Start and stop many parsers
      for i <- 1..10 do
        config = %{
          language: "test#{i}",
          command: "python3",
          args: ["-u", Path.join([__DIR__, "fixtures", "simple_js_parser.py"])],
          timeout: 5000
        }
        
        {:ok, port_id} = PortSupervisor.start_port(PortSupervisor, config)
        # Do some work
        {:ok, _} = PortSupervisor.call_port(PortSupervisor, port_id, "const x = 1", 1000)
        # Stop it
        PortSupervisor.stop_port(PortSupervisor, port_id)
      end
      
      # Wait for cleanup
      Process.sleep(1000)
      
      # Check Python process count hasn't increased significantly
      {final_output, _exit_code} = System.cmd("pgrep", ["-c", "python3"], stderr_to_stdout: true)
      final_count = case Integer.parse(String.trim(final_output)) do
        {num, _} -> num
        :error -> 0
      end
      
      # Allow for some system Python processes, but no accumulation from our tests
      assert final_count <= initial_count + 2
    end
  end
end