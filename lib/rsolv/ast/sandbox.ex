defmodule Rsolv.AST.Sandbox do
  @moduledoc """
  BEAM-native process sandboxing for parser processes.

  Leverages BEAM's strengths:
  - Process isolation (each parser in its own BEAM process)
  - Memory limits via spawn_opt max_heap_size
  - CPU scheduling via BEAM scheduler and reductions
  - Timeouts via GenServer calls and Task.await_many
  - Crash containment via supervisors (one_for_one strategy)
  - Resource monitoring via Process.info
  - Port isolation with restricted environments
  - ETS-based resource tracking
  """

  require Logger

  @default_limits %{
    # ~256MB max heap
    max_heap_size: 64_000_000,
    # 30 seconds
    timeout_ms: 30_000,
    # Limit CPU time per operation
    max_reductions: 2_000_000,
    # Only allow one port per parser
    max_ports: 1,
    # Limit ETS table creation
    max_ets_tables: 5
  }

  # Reserved for future use: restrict dangerous modules
  # @restricted_modules [
  #   # Network modules
  #   :gen_tcp, :gen_udp, :inet, :socket,
  #   # File system modules (allow only safe reads)
  #   # :file is allowed but monitored
  #   # Dangerous system modules
  #   :os, :erlang, :erts_debug, :erl_ddll,
  #   # Code loading
  #   :code, :erts_internal
  # ]

  @doc """
  Creates sandbox configuration optimized for BEAM processes.
  """
  def create_beam_sandbox_config(parser_type, options \\ %{}) do
    limits = Map.merge(@default_limits, options[:limits] || %{})

    %{
      type: parser_type,
      limits: limits,
      spawn_opts: [
        max_heap_size: limits.max_heap_size,
        monitor: true,
        # Don't link to avoid cascade failures
        link: false
      ],
      allowed_modules: get_allowed_modules(parser_type),
      port_env: build_restricted_port_env(parser_type, options[:security] || %{}),
      resource_tracker_name:
        :"sandbox_#{parser_type}_#{:crypto.strong_rand_bytes(4) |> Base.encode16(case: :lower)}",
      security: options[:security] || %{}
    }
  end

  @doc """
  Spawns a sandboxed parser process with BEAM-native isolation.
  """
  def spawn_sandboxed_parser(config, module, function, args) do
    resource_tracker = start_resource_tracker(config)

    # Spawn with memory and other limits
    _spawn_opts =
      config.spawn_opts ++
        [
          {:"$initial_call", {__MODULE__, :sandboxed_wrapper, 3}}
        ]

    try do
      {pid, monitor_ref} =
        spawn_monitor(fn ->
          sandboxed_wrapper(config, resource_tracker, {module, function, args})
        end)

      # Start monitoring process resources
      start_resource_monitor(pid, config, resource_tracker)

      {:ok, pid, monitor_ref, resource_tracker}
    catch
      :error, reason ->
        stop_resource_tracker(resource_tracker)
        {:error, "Failed to spawn sandboxed process: #{inspect(reason)}"}
    end
  end

  @doc """
  Spawns a sandboxed port process with additional restrictions.
  """
  def spawn_sandboxed_port(config, command, args) do
    resource_tracker = start_resource_tracker(config)

    # Set process limits for the current process
    Process.flag(:trap_exit, true)
    Process.flag(:max_heap_size, config.limits.max_heap_size)

    # Track port creation
    safe_ets_update_counter(resource_tracker, :ports_created, 1, {:ports_created, 0})

    case :ets.lookup(resource_tracker, :ports_created) do
      [{:ports_created, count}] when count > config.limits.max_ports ->
        stop_resource_tracker(resource_tracker)
        {:error, :port_limit_exceeded}

      _ ->
        # Build restricted port options
        # Set working directory to the directory containing the command for bundler/npm
        command_dir = Path.dirname(command)

        port_opts = [
          :binary,
          :exit_status,
          :use_stdio,
          args: args,
          env: config.port_env,
          cd: command_dir
        ]

        try do
          port = Port.open({:spawn_executable, command}, port_opts)

          # Monitor port and enforce limits
          monitor_port_resources(port, config, resource_tracker)

          {:ok, port, resource_tracker}
        catch
          :error, reason ->
            stop_resource_tracker(resource_tracker)
            {:error, reason}
        end
    end
  end

  @doc """
  Monitors resource usage of a sandboxed process.
  """
  def get_resource_usage(pid, resource_tracker) do
    case Process.info(pid, [:memory, :total_heap_size, :reductions, :message_queue_len]) do
      nil ->
        {:error, :process_dead}

      info ->
        beam_stats = %{
          memory_bytes: info[:memory] || 0,
          heap_size: info[:total_heap_size] || 0,
          reductions: info[:reductions] || 0,
          message_queue_length: info[:message_queue_len] || 0
        }

        # Get tracked resources
        tracked_stats =
          case :ets.lookup(resource_tracker, :stats) do
            [{:stats, stats}] -> stats
            [] -> %{}
          end

        {:ok, Map.merge(beam_stats, tracked_stats)}
    end
  end

  @doc """
  Enforces resource limits on a running process.
  """
  def enforce_limits(pid, config) do
    case Process.info(pid, [:reductions, :memory]) do
      # Process already dead
      nil ->
        :ok

      info ->
        # Check reduction limit (CPU usage)
        if info[:reductions] > config.limits.max_reductions do
          Logger.warning("Process #{inspect(pid)} exceeded reduction limit: #{info[:reductions]}")
          Process.exit(pid, :reduction_limit_exceeded)
          {:killed, :reduction_limit}
        else
          :ok
        end
    end
  end

  @doc """
  Cleans up sandbox resources.
  """
  def cleanup_sandbox(resource_tracker) do
    stop_resource_tracker(resource_tracker)
    :ok
  end

  # Private functions

  # Wrapper function that runs in the sandboxed process
  defp sandboxed_wrapper(config, resource_tracker, {module, function, args}) do
    # Set process limits
    Process.flag(:max_heap_size, config.limits.max_heap_size)
    Process.flag(:trap_exit, true)

    # Periodically check reduction limits
    :timer.apply_interval(1000, __MODULE__, :enforce_limits, [self(), config])

    # Track resource usage
    safe_ets_insert(resource_tracker, {:process_started, System.monotonic_time(:millisecond)})

    try do
      # Execute the actual function
      apply(module, function, args)
    catch
      class, reason ->
        Logger.error("Sandboxed process crashed: #{class}:#{inspect(reason)}")
        {:error, {class, reason}}
    after
      # Clean up
      safe_ets_insert(resource_tracker, {:process_ended, System.monotonic_time(:millisecond)})
    end
  end

  defp get_allowed_modules("javascript"), do: [:file, :binary, :string, :json]
  defp get_allowed_modules("typescript"), do: [:file, :binary, :string, :json]
  defp get_allowed_modules("python"), do: [:file, :binary, :string, :unicode]
  defp get_allowed_modules("ruby"), do: [:file, :binary, :string]
  defp get_allowed_modules("php"), do: [:file, :binary, :string]
  defp get_allowed_modules("java"), do: [:file, :binary, :string]
  defp get_allowed_modules("go"), do: [:file, :binary, :string]
  defp get_allowed_modules(_), do: [:file, :binary, :string]

  defp build_restricted_port_env(parser_type, security_config) do
    # Build PATH that includes OTP bin directory for Elixir parser
    # In CI: INSTALL_DIR_FOR_OTP is set by erlef/setup-beam
    # In local dev: Erlang is usually in system PATH already
    path =
      case System.get_env("INSTALL_DIR_FOR_OTP") do
        nil ->
          # Local development: use current PATH or fall back to standard paths
          System.get_env("PATH", "/usr/local/bin:/usr/bin:/bin")

        otp_dir ->
          # CI environment: prepend OTP bin directory to PATH
          otp_bin = Path.join(otp_dir, "bin")
          current_path = System.get_env("PATH", "/usr/bin:/bin")
          "#{otp_bin}:#{current_path}"
      end

    base_env = [
      {~c"PATH", String.to_charlist(path)},
      {~c"HOME", ~c"/tmp"},
      {~c"TMPDIR", ~c"/tmp"},
      {~c"RSOLV_SANDBOX", ~c"beam"},
      # Disable network for common tools
      {~c"NO_PROXY", ~c"*"},
      {~c"http_proxy", ~c""},
      {~c"https_proxy", ~c""},
      # Limit resource discovery
      {~c"LANG", ~c"C"},
      {~c"LC_ALL", ~c"C"}
    ]

    # Add security environment variables
    security_env = [
      {~c"SECURITY_READ_ONLY_FS",
       if(security_config[:read_only_fs], do: ~c"true", else: ~c"false")},
      {~c"SECURITY_NO_NETWORK", if(security_config[:no_network], do: ~c"true", else: ~c"false")}
    ]

    base_env = base_env ++ security_env

    # Add parser-specific restrictions
    case parser_type do
      "javascript" ->
        base_env ++
          [
            {~c"NODE_OPTIONS", ~c"--max-old-space-size=128 --no-warnings"},
            {~c"NPM_CONFIG_CACHE", ~c"/tmp/.npm"}
          ]

      "python" ->
        base_env ++
          [
            {~c"PYTHONPATH", ~c"/tmp"},
            {~c"PYTHONDONTWRITEBYTECODE", ~c"1"},
            {~c"PYTHONUNBUFFERED", ~c"1"}
          ]

      "ruby" ->
        base_env ++
          [
            {~c"GEM_HOME", ~c"/tmp/.gems"},
            {~c"BUNDLE_SILENCE_ROOT_WARNING", ~c"1"}
          ]

      _ ->
        base_env
    end
  end

  defp start_resource_tracker(config) do
    table_name = config.resource_tracker_name
    :ets.new(table_name, [:set, :public, :named_table])

    # Initialize counters
    :ets.insert(table_name, {:ports_created, 0})
    :ets.insert(table_name, {:ets_tables_created, 0})
    :ets.insert(table_name, {:stats, %{}})

    table_name
  end

  defp stop_resource_tracker(resource_tracker) do
    if :ets.whereis(resource_tracker) != :undefined do
      :ets.delete(resource_tracker)
    end
  end

  # Safe ETS operations to prevent crashes when tables are deleted during cleanup
  defp safe_ets_insert(table, key_value) do
    try do
      :ets.insert(table, key_value)
    catch
      # Table doesn't exist, ignore gracefully
      :error, :badarg -> :ok
    end
  end

  defp safe_ets_update_counter(table, key, increment, default) do
    try do
      :ets.update_counter(table, key, increment, default)
    catch
      # Table doesn't exist, ignore gracefully
      :error, :badarg -> :ok
    end
  end

  defp start_resource_monitor(pid, config, resource_tracker) do
    # Monitor process every second
    spawn_link(fn ->
      monitor_loop(pid, config, resource_tracker)
    end)
  end

  defp monitor_loop(pid, config, resource_tracker) do
    case Process.alive?(pid) do
      true ->
        # Update resource stats
        case get_resource_usage(pid, resource_tracker) do
          {:ok, stats} ->
            safe_ets_insert(resource_tracker, {:stats, stats})

            # Check limits
            if stats.memory_bytes > config.limits.max_heap_size do
              Logger.warning("Process #{inspect(pid)} exceeded memory limit")
              Process.exit(pid, :memory_limit_exceeded)
            end

          _ ->
            :ok
        end

        # Sleep and continue monitoring
        Process.sleep(1000)
        monitor_loop(pid, config, resource_tracker)

      false ->
        # Process died, stop monitoring
        :ok
    end
  end

  defp monitor_port_resources(port, config, resource_tracker) do
    # Start a process to monitor the port
    spawn_link(fn ->
      port_monitor_loop(port, config, resource_tracker)
    end)
  end

  defp port_monitor_loop(port, config, resource_tracker) do
    case Port.info(port) do
      nil ->
        # Port closed
        :ok

      info ->
        # Update port stats
        stats = %{
          port_queue_size: info[:queue_size] || 0,
          port_connected: info[:connected] || false,
          port_memory: info[:memory] || 0
        }

        safe_ets_insert(resource_tracker, {:port_stats, stats})

        # Sleep and continue monitoring
        Process.sleep(1000)
        port_monitor_loop(port, config, resource_tracker)
    end
  end
end
