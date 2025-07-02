defmodule RsolvApi.AST.PortWorker do
  @moduledoc """
  GenServer that manages a single parser Port process.
  Handles communication, health checks, and resource monitoring.
  """
  
  use GenServer
  
  require Logger
  
  alias RsolvApi.AST.Sandbox
  
  defstruct [
    :id,
    :port,
    :config,
    :buffer,
    :requests,
    :health_check_timer,
    :idle_timer,
    :sandbox_config,
    :resource_tracker
  ]
  
  # Client API
  
  def start_link(config) do
    GenServer.start_link(__MODULE__, config)
  end
  
  # Server callbacks
  
  @impl true
  def init(config) do
    Process.flag(:trap_exit, true)
    
    # Create sandbox configuration
    sandbox_config = Sandbox.create_beam_sandbox_config(
      config.language, 
      %{
        limits: config[:sandbox_limits] || %{},
        security: config[:security] || %{}
      }
    )
    
    state = %__MODULE__{
      id: config.id,
      config: config,
      buffer: "",
      requests: %{},
      sandbox_config: sandbox_config
    }
    
    # Start the port with sandboxing
    case start_sandboxed_port(config, sandbox_config) do
      {:ok, port, resource_tracker} ->
        state = %{state | port: port, resource_tracker: resource_tracker}
        
        # Schedule health checks if configured
        state = if config[:health_check_interval] do
          timer = Process.send_after(self(), :health_check, config.health_check_interval)
          %{state | health_check_timer: timer}
        else
          state
        end
        
        # Schedule memory monitoring if configured
        state = if config[:max_heap_size] do
          timer = Process.send_after(self(), :memory_check, 1000)  # Check every second
          %{state | health_check_timer: timer}  # Reuse timer field for simplicity
        else
          state
        end
        
        # Schedule idle timeout if configured
        state = if config[:idle_timeout] do
          timer = Process.send_after(self(), :idle_timeout, config.idle_timeout)
          %{state | idle_timer: timer}
        else
          state
        end
        
        {:ok, state}
        
      {:error, reason} ->
        {:stop, reason}
    end
  end
  
  @impl true
  def handle_cast({:send, message}, state) do
    # Send raw message to port
    request = %{
      "id" => generate_request_id(),
      "command" => message
    }
    
    send_to_port(state.port, request)
    
    # Reset idle timer
    state = reset_idle_timer(state)
    
    {:noreply, state}
  end
  
  @impl true
  def handle_call({:call, command}, from, state) do
    request_id = generate_request_id()
    
    request = %{
      "id" => request_id,
      "command" => command
    }
    
    # Store the pending request
    state = %{state | requests: Map.put(state.requests, request_id, from)}
    
    # Send to port
    send_to_port(state.port, request)
    
    # Reset idle timer
    state = reset_idle_timer(state)
    
    {:noreply, state}
  end
  
  @impl true
  def handle_info({port, {:data, data}}, %{port: port} = state) when is_port(port) do
    # Accumulate data in buffer
    state = %{state | buffer: state.buffer <> data}
    
    # Try to parse complete messages
    {messages, remaining} = parse_messages(state.buffer)
    state = %{state | buffer: remaining}
    
    # Process each complete message
    state = Enum.reduce(messages, state, &process_message/2)
    
    {:noreply, state}
  end
  
  @impl true
  def handle_info({port, {:exit_status, status}}, %{port: port} = state) do
    Logger.warning("Port exited with status #{status}")
    {:stop, {:port_exit, status}, state}
  end
  
  @impl true
  def handle_info({:EXIT, port, reason}, %{port: port} = state) do
    Logger.warning("Port terminated: #{inspect(reason)}")
    {:stop, {:port_terminated, reason}, state}
  end
  
  @impl true
  def handle_info(:health_check, state) do
    # Perform health check
    request = %{
      "id" => "health_check_#{System.unique_integer([:positive])}",
      "command" => "HEALTH_CHECK"
    }
    
    send_to_port(state.port, request)
    
    # Schedule next health check
    timer = Process.send_after(self(), :health_check, state.config.health_check_interval)
    state = %{state | health_check_timer: timer}
    
    {:noreply, state}
  end
  
  @impl true
  def handle_info(:idle_timeout, state) do
    Logger.info("Port #{state.id} idle timeout reached")
    # Notify supervisor to clean up
    notify_supervisor_cleanup(state.id)
    {:stop, :normal, state}
  end

  @impl true
  def handle_info(:memory_check, state) do
    # Check memory usage
    max_memory = state.config[:max_heap_size]
    current_memory = case Process.info(self(), :memory) do
      {:memory, bytes} -> bytes
      nil -> 0
    end
    
    if current_memory > max_memory do
      Logger.warning("Port #{state.id} exceeded memory limit: #{current_memory} > #{max_memory}")
      {:stop, :memory_limit_exceeded, state}
    else
      # Schedule next memory check
      timer = Process.send_after(self(), :memory_check, 1000)
      state = %{state | health_check_timer: timer}
      {:noreply, state}
    end
  end
  
  @impl true
  def terminate(reason, state) do
    # Clean up timers
    if state.health_check_timer, do: Process.cancel_timer(state.health_check_timer)
    if state.idle_timer, do: Process.cancel_timer(state.idle_timer)
    
    # Clean up sandbox resources first
    if state.resource_tracker do
      Sandbox.cleanup_sandbox(state.resource_tracker)
    end
    
    # Kill the port process forcefully if it's still alive
    if state.port && port_alive?(state.port) do
      # First try to get the OS pid
      case Port.info(state.port, :os_pid) do
        {:os_pid, os_pid} ->
          # Send SIGTERM first
          System.cmd("kill", ["-TERM", "#{os_pid}"], stderr_to_stdout: true)
          # Give it a moment to clean up
          Process.sleep(100)
          # If still running, send SIGKILL
          System.cmd("kill", ["-KILL", "#{os_pid}"], stderr_to_stdout: true)
        _ ->
          # Fallback to port close if we can't get OS pid
          Port.close(state.port)
      end
    end
    
    # Reply to any pending requests
    Enum.each(state.requests, fn {_id, from} ->
      GenServer.reply(from, {:error, :port_terminated})
    end)
    
    # Notify supervisor to clean up unless already notified
    unless reason == :normal do
      notify_supervisor_cleanup(state.id)
    end
    
    :ok
  end
  
  # Private functions
  
  defp start_sandboxed_port(config, sandbox_config) do
    command = config.command
    args = config[:args] || []
    
    # Find the command in PATH
    command_path = case System.find_executable(command) do
      nil -> command  # Use as-is, might be full path
      path -> path
    end
    
    # Use sandbox to spawn the port with restrictions
    Sandbox.spawn_sandboxed_port(sandbox_config, command_path, args)
  end
  
  
  defp send_to_port(port, request) do
    json = JSON.encode!(request)
    Port.command(port, json <> "\n")
  end
  
  defp parse_messages(buffer) do
    lines = String.split(buffer, "\n", trim: true)
    
    case lines do
      [] -> 
        {[], buffer}
        
      lines ->
        # Check if last line is incomplete
        {complete_lines, incomplete} = if String.ends_with?(buffer, "\n") do
          {lines, ""}
        else
          {Enum.drop(lines, -1), List.last(lines)}
        end
        
        # Parse each complete line as JSON
        messages = Enum.flat_map(complete_lines, fn line ->
          case JSON.decode(line) do
            {:ok, message} -> [message]
            {:error, _} -> [:invalid_json]
          end
        end)
        
        {messages, incomplete}
    end
  end
  
  defp process_message(message, state) do
    case message do
      %{"id" => request_id} = response ->
        # Check if this is a response to a pending request
        case Map.pop(state.requests, request_id) do
          {nil, requests} ->
            # Not a tracked request, ignore
            %{state | requests: requests}
            
          {from, requests} ->
            # Reply to the waiting process
            reply = case response do
              %{"error" => _error} -> {:ok, response}  # Return full response with error
              %{"result" => result} -> {:ok, result}
              _ -> {:ok, response}
            end
            
            GenServer.reply(from, reply)
            %{state | requests: requests}
        end
        
      :invalid_json ->
        # Invalid JSON received - reply with error to pending requests
        Enum.each(state.requests, fn {_id, from} ->
          GenServer.reply(from, {:error, :invalid_response})
        end)
        %{state | requests: %{}}
        
      _ ->
        # Unrecognized message format
        state
    end
  end
  
  defp reset_idle_timer(state) do
    if state.idle_timer do
      Process.cancel_timer(state.idle_timer)
      timer = Process.send_after(self(), :idle_timeout, state.config.idle_timeout)
      %{state | idle_timer: timer}
    else
      state
    end
  end
  
  defp port_alive?(port) do
    case Port.info(port) do
      nil -> false
      _ -> true
    end
  end
  
  defp generate_request_id do
    :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
  end
  
  defp notify_supervisor_cleanup(port_id) do
    # Clean up ETS entries
    :ets.delete(:port_registry, port_id)
    :ets.delete(:port_stats, port_id)
  end
end