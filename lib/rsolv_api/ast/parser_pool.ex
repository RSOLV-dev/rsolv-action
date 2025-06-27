defmodule RsolvApi.AST.ParserPool do
  @moduledoc """
  Manages pools of parser processes for high-performance AST parsing.
  
  Features:
  - Per-language parser pools with configurable size
  - Pre-warming on startup for zero cold-start latency
  - Automatic scaling based on demand
  - Health monitoring and crash recovery
  - Detailed metrics and telemetry
  """
  
  use GenServer
  require Logger
  
  alias RsolvApi.AST.{PortSupervisor, ParserRegistry}
  
  @default_pool_size 3
  @default_timeout 5_000
  @health_check_interval 30_000
  @scale_check_interval 5_000
  
  defmodule PoolState do
    @enforce_keys [:languages, :pool_size, :config]
    defstruct [
      :languages,
      :pool_size,
      :config,
      pools: %{},
      metrics: %{},
      scaling_enabled: false,
      pre_warm: true
    ]
  end
  
  defmodule ParserInfo do
    @enforce_keys [:id, :language, :status]
    defstruct [
      :id,
      :language,
      :status,  # :available | :busy | :warming
      :warmed,
      :created_at,
      :last_used_at,
      :successful_parses,
      :failed_parses,
      :total_parse_time_ms,
      :checkout_count,
      :current_holder
    ]
  end
  
  # Client API
  
  def start_link(config) do
    GenServer.start_link(__MODULE__, config, name: __MODULE__)
  end
  
  def checkout(pool \\ __MODULE__, language, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, @default_timeout)
    GenServer.call(pool, {:checkout, language}, timeout)
  end
  
  def checkin(pool \\ __MODULE__, language, parser_id) do
    GenServer.cast(pool, {:checkin, language, parser_id})
  end
  
  def report_crash(pool \\ __MODULE__, language, parser_id) do
    GenServer.cast(pool, {:report_crash, language, parser_id})
  end
  
  def report_success(pool \\ __MODULE__, language, parser_id, metrics) do
    GenServer.cast(pool, {:report_success, language, parser_id, metrics})
  end
  
  def report_failure(pool \\ __MODULE__, language, parser_id, reason) do
    GenServer.cast(pool, {:report_failure, language, parser_id, reason})
  end
  
  def get_pool_status(pool \\ __MODULE__) do
    GenServer.call(pool, :get_pool_status)
  end
  
  def get_parser_status(pool \\ __MODULE__, language) do
    GenServer.call(pool, {:get_parser_status, language})
  end
  
  def get_metrics(pool \\ __MODULE__) do
    GenServer.call(pool, :get_metrics)
  end
  
  def trigger_scaling(pool \\ __MODULE__) do
    GenServer.cast(pool, :trigger_scaling)
  end
  
  # Server callbacks
  
  @impl true
  def init(config) do
    state = %PoolState{
      languages: config[:languages] || ["javascript"],
      pool_size: config[:pool_size] || @default_pool_size,
      config: config,
      pools: %{},
      metrics: %{},
      scaling_enabled: config[:enable_autoscaling] || false,
      pre_warm: config[:pre_warm] != false
    }
    
    # Initialize pools for each language
    state = Enum.reduce(state.languages, state, fn language, acc ->
      initialize_language_pool(acc, language)
    end)
    
    # Schedule periodic tasks
    if state.scaling_enabled do
      Process.send_after(self(), :check_scaling, @scale_check_interval)
    end
    Process.send_after(self(), :health_check, @health_check_interval)
    
    {:ok, state}
  end
  
  @impl true
  def handle_call({:checkout, language}, from, state) do
    case find_available_parser(state, language) do
      {:ok, parser_id} ->
        # Mark parser as busy
        state = update_parser_status(state, language, parser_id, :busy, from)
        state = record_checkout(state, language, parser_id)
        {:reply, {:ok, parser_id}, state}
        
      {:error, :no_available} ->
        # Queue the request or timeout
        if state.config[:queue_requests] do
          # TODO: Implement request queueing
          {:reply, {:error, :timeout}, state}
        else
          {:reply, {:error, :timeout}, state}
        end
        
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end
  
  @impl true
  def handle_call(:get_pool_status, _from, state) do
    status = Enum.reduce(state.pools, %{}, fn {language, parsers}, acc ->
      counts = Enum.reduce(parsers, %{available: 0, busy: 0, warming: 0}, fn {_id, info}, counts ->
        case info.status do
          :available -> %{counts | available: counts.available + 1}
          :busy -> %{counts | busy: counts.busy + 1}
          :warming -> %{counts | warming: counts.warming + 1}
        end
      end)
      
      Map.put(acc, language, %{
        available: counts.available,
        busy: counts.busy,
        total: map_size(parsers)
      })
    end)
    
    {:reply, status, state}
  end
  
  @impl true
  def handle_call({:get_parser_status, language}, _from, state) do
    parsers = Map.get(state.pools, language, %{})
    status = Enum.reduce(parsers, %{}, fn {id, info}, acc ->
      Map.put(acc, id, %{
        warmed: info.warmed,
        status: info.status,
        created_at: info.created_at,
        last_used_at: info.last_used_at,
        successful_parses: info.successful_parses,
        failed_parses: info.failed_parses
      })
    end)
    
    {:reply, status, state}
  end
  
  @impl true
  def handle_call(:get_metrics, _from, state) do
    metrics = Enum.reduce(state.metrics, %{}, fn {language, lang_metrics}, acc ->
      Map.put(acc, language, calculate_metrics(lang_metrics, state.pools[language] || %{}))
    end)
    
    {:reply, metrics, state}
  end
  
  @impl true
  def handle_cast({:checkin, language, parser_id}, state) do
    state = update_parser_status(state, language, parser_id, :available, nil)
    state = record_checkin(state, language, parser_id)
    {:noreply, state}
  end
  
  @impl true
  def handle_cast({:report_crash, language, parser_id}, state) do
    Logger.warning("Parser crashed: #{language}/#{parser_id}")
    
    # Remove crashed parser
    state = remove_parser(state, language, parser_id)
    
    # Spawn replacement
    state = spawn_parser(state, language)
    
    {:noreply, state}
  end
  
  @impl true
  def handle_cast({:report_success, language, parser_id, metrics}, state) do
    parse_time = metrics[:parse_time_ms] || 0
    
    state = %{state |
      pools: Map.update(state.pools, language, %{}, fn lang_pools ->
        Map.update(lang_pools, parser_id, nil, fn info ->
          %{info |
            successful_parses: info.successful_parses + 1,
            total_parse_time_ms: info.total_parse_time_ms + parse_time,
            last_used_at: System.system_time(:second)
          }
        end)
      end)
    }
    
    {:noreply, state}
  end
  
  @impl true
  def handle_cast({:report_failure, language, parser_id, _reason}, state) do
    state = %{state |
      pools: Map.update(state.pools, language, %{}, fn lang_pools ->
        Map.update(lang_pools, parser_id, nil, fn info ->
          %{info |
            failed_parses: info.failed_parses + 1,
            last_used_at: System.system_time(:second)
          }
        end)
      end)
    }
    
    {:noreply, state}
  end
  
  @impl true
  def handle_cast(:trigger_scaling, state) do
    if state.scaling_enabled do
      state = auto_scale(state)
      {:noreply, state}
    else
      {:noreply, state}
    end
  end
  
  @impl true
  def handle_info(:health_check, state) do
    # Check health of all parsers
    state = Enum.reduce(state.pools, state, fn {language, parsers}, acc ->
      Enum.reduce(parsers, acc, fn {id, info}, acc2 ->
        if info.status == :available && should_health_check?(info) do
          perform_health_check(acc2, language, id)
        else
          acc2
        end
      end)
    end)
    
    Process.send_after(self(), :health_check, @health_check_interval)
    {:noreply, state}
  end
  
  @impl true
  def handle_info(:check_scaling, state) do
    if state.scaling_enabled do
      state = auto_scale(state)
      Process.send_after(self(), :check_scaling, @scale_check_interval)
    end
    
    {:noreply, state}
  end
  
  @impl true
  def handle_info({:parser_warmed, language, parser_id}, state) do
    state = %{state |
      pools: Map.update(state.pools, language, %{}, fn lang_pools ->
        Map.update(lang_pools, parser_id, nil, fn info ->
          %{info | warmed: true, status: :available}
        end)
      end)
    }
    
    {:noreply, state}
  end
  
  # Private functions
  
  defp initialize_language_pool(state, language) do
    parsers = if state.pre_warm do
      # Spawn and warm parsers immediately
      spawn_parsers(state, language, state.pool_size)
    else
      # Lazy initialization - parsers created on demand
      %{}
    end
    
    %{state |
      pools: Map.put(state.pools, language, parsers),
      metrics: Map.put(state.metrics, language, %{
        checkouts: 0,
        checkins: 0,
        total_wait_time_ms: 0,
        successful_parses: 0,
        failed_parses: 0
      })
    }
  end
  
  defp spawn_parsers(state, language, count) do
    1..count
    |> Enum.reduce(%{}, fn _, acc ->
      parser_id = spawn_single_parser(language)
      
      info = %ParserInfo{
        id: parser_id,
        language: language,
        status: if(state.pre_warm, do: :warming, else: :available),
        warmed: false,
        created_at: System.system_time(:second),
        last_used_at: nil,
        successful_parses: 0,
        failed_parses: 0,
        total_parse_time_ms: 0,
        checkout_count: 0,
        current_holder: nil
      }
      
      if state.pre_warm do
        # Async warm the parser
        pool_pid = self()
        Task.start(fn ->
          warm_parser(language, parser_id)
          send(pool_pid, {:parser_warmed, language, parser_id})
        end)
      end
      
      Map.put(acc, parser_id, info)
    end)
  end
  
  defp spawn_single_parser(language) do
    case ParserRegistry.get_parser(language) do
      {:ok, parser_config} ->
        config = %{
          language: language,
          command: parser_config.command,
          args: parser_config.args,
          timeout: parser_config.timeout,
          pooled: true
        }
        
        case PortSupervisor.start_port(PortSupervisor, config) do
          {:ok, parser_id} -> parser_id
          {:error, reason} ->
            Logger.error("Failed to spawn parser for #{language}: #{inspect(reason)}")
            nil
        end
        
      {:error, _} ->
        Logger.error("No parser configuration for #{language}")
        nil
    end
  end
  
  defp spawn_parser(state, language) do
    parser_id = spawn_single_parser(language)
    
    if parser_id do
      info = %ParserInfo{
        id: parser_id,
        language: language,
        status: :available,
        warmed: false,
        created_at: System.system_time(:second),
        last_used_at: nil,
        successful_parses: 0,
        failed_parses: 0,
        total_parse_time_ms: 0,
        checkout_count: 0,
        current_holder: nil
      }
      
      %{state | 
        pools: Map.update(state.pools, language, %{parser_id => info}, fn lang_pools ->
          Map.put(lang_pools, parser_id, info)
        end)
      }
    else
      state
    end
  end
  
  defp warm_parser(language, parser_id) do
    # Send health check to warm up the parser
    health_check_cmd = %{
      "command" => "HEALTH_CHECK"
    }
    
    case PortSupervisor.call_port(nil, parser_id, Jason.encode!(health_check_cmd), 5_000) do
      {:ok, _} ->
        Logger.debug("Parser warmed: #{language}/#{parser_id}")
        true
      {:error, reason} ->
        Logger.warning("Failed to warm parser #{language}/#{parser_id}: #{inspect(reason)}")
        false
    end
  end
  
  defp find_available_parser(state, language) do
    parsers = Map.get(state.pools, language, %{})
    
    available = Enum.find(parsers, fn {_id, info} ->
      info.status == :available && info.warmed
    end)
    
    case available do
      {parser_id, _info} -> {:ok, parser_id}
      nil ->
        # Check if we have any parsers at all
        if map_size(parsers) == 0 && !state.pre_warm do
          # Lazy initialization - spawn parser on demand
          state = spawn_parser(state, language)
          find_available_parser(state, language)
        else
          {:error, :no_available}
        end
    end
  end
  
  defp update_parser_status(state, language, parser_id, status, holder) do
    case get_in(state.pools, [language, parser_id]) do
      nil -> state
      _info ->
        %{state |
          pools: Map.update(state.pools, language, %{}, fn lang_pools ->
            Map.update(lang_pools, parser_id, nil, fn info ->
              %{info | status: status, current_holder: holder}
            end)
          end)
        }
    end
  end
  
  defp remove_parser(state, language, parser_id) do
    %{state |
      pools: Map.update(state.pools, language, %{}, &Map.delete(&1, parser_id))
    }
  end
  
  defp record_checkout(state, language, parser_id) do
    state = %{state |
      metrics: Map.update(state.metrics, language, %{checkouts: 1}, fn lang_metrics ->
        Map.update(lang_metrics, :checkouts, 1, &(&1 + 1))
      end)
    }
    
    %{state |
      pools: Map.update(state.pools, language, %{}, fn lang_pools ->
        Map.update(lang_pools, parser_id, nil, fn info ->
          %{info | checkout_count: info.checkout_count + 1}
        end)
      end)
    }
  end
  
  defp record_checkin(state, language, _parser_id) do
    %{state |
      metrics: Map.update(state.metrics, language, %{checkins: 1}, fn lang_metrics ->
        Map.update(lang_metrics, :checkins, 1, &(&1 + 1))
      end)
    }
  end
  
  defp calculate_metrics(lang_metrics, parsers) do
    total_parsers = map_size(parsers)
    busy_parsers = Enum.count(parsers, fn {_id, info} -> info.status == :busy end)
    
    total_successful = Enum.reduce(parsers, 0, fn {_id, info}, acc ->
      acc + info.successful_parses
    end)
    
    total_failed = Enum.reduce(parsers, 0, fn {_id, info}, acc ->
      acc + info.failed_parses
    end)
    
    total_parse_time = Enum.reduce(parsers, 0, fn {_id, info}, acc ->
      acc + info.total_parse_time_ms
    end)
    
    avg_parse_time = if total_successful > 0 do
      total_parse_time / total_successful
    else
      0
    end
    
    health_score = if total_successful + total_failed > 0 do
      total_successful / (total_successful + total_failed)
    else
      1.0
    end
    
    %{
      checkouts: lang_metrics[:checkouts] || 0,
      checkins: lang_metrics[:checkins] || 0,
      utilization: if(total_parsers > 0, do: busy_parsers / total_parsers, else: 0),
      avg_wait_time_ms: 0, # TODO: Implement wait time tracking
      successful_parses: total_successful,
      failed_parses: total_failed,
      avg_parse_time_ms: avg_parse_time,
      health_score: health_score
    }
  end
  
  defp should_health_check?(info) do
    # Health check if not used in last 5 minutes
    case info.last_used_at do
      nil -> true
      last_used ->
        System.system_time(:second) - last_used > 300
    end
  end
  
  defp perform_health_check(state, language, parser_id) do
    Task.start(fn ->
      case warm_parser(language, parser_id) do
        false ->
          # Parser failed health check, report crash
          GenServer.cast(self(), {:report_crash, language, parser_id})
        _ ->
          :ok
      end
    end)
    
    state
  end
  
  defp auto_scale(state) do
    Enum.reduce(state.pools, state, fn {language, parsers}, acc ->
      metrics = calculate_metrics(acc.metrics[language], parsers)
      utilization = metrics.utilization
      
      cond do
        # Scale up if high utilization
        utilization > 0.8 && should_scale_up?(acc, language) ->
          scale_up(acc, language)
          
        # Scale down if low utilization
        utilization < 0.2 && should_scale_down?(acc, language) ->
          scale_down(acc, language)
          
        true ->
          acc
      end
    end)
  end
  
  defp should_scale_up?(state, language) do
    current_size = map_size(state.pools[language] || %{})
    max_size = state.config[:max_pool_size] || state.pool_size * 2
    current_size < max_size
  end
  
  defp should_scale_down?(state, language) do
    current_size = map_size(state.pools[language] || %{})
    min_size = state.config[:min_pool_size] || 2
    scale_down_after = state.config[:scale_down_after_ms] || 300_000  # 5 minutes default
    
    if current_size > min_size do
      # Check if any parser has been idle long enough
      parsers = state.pools[language] || %{}
      now = System.system_time(:millisecond)
      
      Enum.any?(parsers, fn {_id, info} ->
        info.status == :available &&
        (info.last_used_at == nil || 
         now - info.last_used_at * 1000 > scale_down_after)
      end)
    else
      false
    end
  end
  
  defp scale_up(state, language) do
    Logger.info("Scaling up #{language} pool")
    spawn_parser(state, language)
  end
  
  defp scale_down(state, language) do
    Logger.info("Scaling down #{language} pool")
    
    # Find least recently used available parser
    parsers = state.pools[language] || %{}
    
    lru_parser = parsers
    |> Enum.filter(fn {_id, info} -> info.status == :available end)
    |> Enum.min_by(fn {_id, info} -> info.last_used_at || 0 end, fn -> nil end)
    
    case lru_parser do
      {parser_id, _info} ->
        # Stop the parser
        try do
          PortSupervisor.stop_port(PortSupervisor, parser_id)
        rescue
          _ -> :ok  # Ignore errors - parser might already be dead
        end
        remove_parser(state, language, parser_id)
        
      nil ->
        state
    end
  end
end