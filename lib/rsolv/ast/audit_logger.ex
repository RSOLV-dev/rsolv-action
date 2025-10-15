defmodule Rsolv.AST.AuditLogger do
  @moduledoc """
  Comprehensive audit logging for AST service security events.

  Provides:
  - Structured event logging with severity levels
  - Correlation ID tracking for related events
  - Buffered persistence to reduce I/O
  - Query and analysis capabilities
  - Compliance-ready export formats
  - Integration with existing security components
  """

  use GenServer
  require Logger

  @version "1.0.0"
  @buffer_size 100
  # 5 seconds
  @flush_interval 5_000

  # Severity mapping for event types
  @severity_map %{
    # Info level events
    parser_spawned: :info,
    session_created: :info,
    file_encrypted: :info,
    ast_parsed: :info,
    session_cleaned: :info,

    # Warning level events
    rate_limit_exceeded: :warning,
    parser_timeout: :warning,
    high_memory_usage: :warning,

    # Error level events
    parser_crashed: :error,
    encryption_failed: :error,
    storage_error: :error,

    # Critical level events
    malicious_input_detected: :critical,
    code_exfiltration_attempt: :critical,
    unauthorized_access: :critical,
    security_breach: :critical
  }

  # Sensitive field patterns for sanitization

  defstruct [
    :buffer,
    :storage_backend,
    :retention_config,
    :flush_timer
  ]

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Log an audit event with metadata.
  """
  def log_event(event_type, metadata, opts \\ []) do
    event = build_event(event_type, metadata, opts)

    GenServer.cast(__MODULE__, {:log_event, event})

    # Also log to standard logger for immediate visibility
    Logger.info("AUDIT_EVENT: #{event_type}", event)

    event
  end

  @doc """
  Log a security-specific event (called by EnhancedSandbox).
  """
  def log_security_event(event_type, metadata) do
    enhanced_metadata = Map.put(metadata, :category, :security)
    log_event(event_type, enhanced_metadata)
  end

  @doc """
  Generate a correlation ID for tracking related events.
  """
  def generate_correlation_id do
    :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
  end

  @doc """
  Get buffered events (for testing).
  """
  def get_buffer do
    GenServer.call(__MODULE__, :get_buffer)
  end

  @doc """
  Flush buffer to persistent storage.
  """
  def flush_to_storage do
    GenServer.call(__MODULE__, :flush_to_storage)
  end

  @doc """
  Set storage backend (for testing).
  """
  def set_storage_backend(backend) do
    GenServer.call(__MODULE__, {:set_storage_backend, backend})
  end

  @doc """
  Clear the buffer (for testing).
  """
  def clear_buffer do
    GenServer.call(__MODULE__, :clear_buffer)
  end

  @doc """
  Query events by criteria.
  """
  def query_events(criteria) do
    GenServer.call(__MODULE__, {:query_events, criteria})
  end

  @doc """
  Get aggregated security metrics.
  """
  def get_security_metrics do
    GenServer.call(__MODULE__, :get_security_metrics)
  end

  @doc """
  Configure retention policy.
  """
  def configure_retention(config) do
    GenServer.call(__MODULE__, {:configure_retention, config})
  end

  @doc """
  Get current retention configuration.
  """
  def get_retention_config do
    GenServer.call(__MODULE__, :get_retention_config)
  end

  @doc """
  Export events in specified format.
  """
  def export_events(format, criteria) do
    GenServer.call(__MODULE__, {:export_events, format, criteria})
  end

  # Server callbacks

  @impl true
  def init(opts) do
    # Initialize ETS tables for buffering and indexing
    :ets.new(:audit_log_buffer, [:set, :named_table, :public])
    :ets.new(:audit_log_index, [:bag, :named_table, :public])

    state = %__MODULE__{
      buffer: [],
      # Default to ETS for now
      storage_backend: opts[:storage_backend] || :ets,
      retention_config: %{
        max_age_days: 30,
        max_events: 10_000_000
      },
      flush_timer: schedule_flush()
    }

    {:ok, state}
  end

  @impl true
  def handle_cast({:log_event, event}, state) do
    # Add to buffer
    new_buffer = [event | state.buffer]

    # Store in ETS for immediate querying
    :ets.insert(:audit_log_buffer, {event.id, event})

    # Index by correlation ID if present
    if event.correlation_id do
      :ets.insert(:audit_log_index, {event.correlation_id, event.id})
    end

    # Check if buffer should be flushed
    state =
      if length(new_buffer) >= @buffer_size do
        flush_buffer(%{state | buffer: new_buffer})
      else
        %{state | buffer: new_buffer}
      end

    {:noreply, state}
  end

  @impl true
  def handle_call(:get_buffer, _from, state) do
    {:reply, Enum.reverse(state.buffer), state}
  end

  @impl true
  def handle_call(:flush_to_storage, _from, state) do
    {result, new_state} = do_flush_to_storage(state)
    {:reply, result, new_state}
  end

  @impl true
  def handle_call({:set_storage_backend, backend}, _from, state) do
    {:reply, :ok, %{state | storage_backend: backend}}
  end

  @impl true
  def handle_call(:clear_buffer, _from, state) do
    # Clear the in-memory buffer
    {:reply, :ok, %{state | buffer: []}}
  end

  @impl true
  def handle_call({:query_events, criteria}, _from, state) do
    events = query_from_buffer(criteria)
    {:reply, events, state}
  end

  @impl true
  def handle_call(:get_security_metrics, _from, state) do
    metrics = calculate_metrics()
    {:reply, metrics, state}
  end

  @impl true
  def handle_call({:configure_retention, config}, _from, state) do
    {:reply, :ok, %{state | retention_config: config}}
  end

  @impl true
  def handle_call(:get_retention_config, _from, state) do
    {:reply, state.retention_config, state}
  end

  @impl true
  def handle_call({:export_events, format, criteria}, _from, state) do
    result = export_events_as(format, criteria)
    {:reply, result, state}
  end

  @impl true
  def handle_info(:flush_buffer, state) do
    state = flush_buffer(state)
    state = %{state | flush_timer: schedule_flush()}
    {:noreply, state}
  end

  # Private functions

  defp build_event(event_type, metadata, opts) do
    %{
      id: generate_event_id(),
      timestamp: opts[:timestamp] || Rsolv.Time.utc_now(),
      event_type: event_type,
      severity: get_severity(event_type),
      correlation_id: opts[:correlation_id] || generate_correlation_id(),
      metadata: sanitize_metadata(metadata),
      node: node(),
      version: @version
    }
  end

  defp generate_event_id do
    :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
  end

  defp get_severity(event_type) do
    Map.get(@severity_map, event_type, :info)
  end

  defp sanitize_metadata(metadata) do
    Enum.reduce(metadata, %{}, fn {key, value}, acc ->
      sanitized_value =
        if is_sensitive_field?(key) do
          "[REDACTED]"
        else
          value
        end

      Map.put(acc, key, sanitized_value)
    end)
  end

  defp is_sensitive_field?(field) do
    field_str = to_string(field)

    # Check against each pattern - compiled at build time
    Regex.match?(~r/api_key/i, field_str) ||
      Regex.match?(~r/password/i, field_str) ||
      Regex.match?(~r/secret/i, field_str) ||
      Regex.match?(~r/token/i, field_str) ||
      Regex.match?(~r/credit_card/i, field_str) ||
      Regex.match?(~r/ssn/i, field_str) ||
      Regex.match?(~r/private_key/i, field_str)
  end

  defp schedule_flush do
    Process.send_after(self(), :flush_buffer, @flush_interval)
  end

  defp flush_buffer(state) do
    if state.buffer != [] do
      case do_flush_to_storage(state) do
        {{:ok, _}, new_state} -> new_state
        {{:error, _reason}, state} -> state
      end
    else
      state
    end
  end

  defp do_flush_to_storage(state) do
    case state.storage_backend do
      :ets ->
        # Already stored in ETS buffer
        count = length(state.buffer)
        {{:ok, count}, %{state | buffer: []}}

      {:error, reason} ->
        # Simulated storage failure
        {{:error, reason}, state}

      backend ->
        # Future: PostgreSQL or other backend
        Logger.warning("Unknown storage backend: #{inspect(backend)}")
        {{:error, :unknown_backend}, state}
    end
  end

  defp query_from_buffer(criteria) do
    all_events =
      :ets.tab2list(:audit_log_buffer)
      |> Enum.map(fn {_id, event} -> event end)

    # Apply filters
    all_events
    |> filter_by_time_range(criteria[:since], criteria[:until])
    |> filter_by_correlation_id(criteria[:correlation_id])
    |> filter_by_event_type(criteria[:event_type])
    |> filter_by_severity(criteria[:severity])
    |> Enum.sort_by(& &1.timestamp, DateTime)
  end

  defp filter_by_time_range(events, nil, nil), do: events

  defp filter_by_time_range(events, since, until) do
    Enum.filter(events, fn event ->
      (is_nil(since) or DateTime.compare(event.timestamp, since) != :lt) and
        (is_nil(until) or DateTime.compare(event.timestamp, until) != :gt)
    end)
  end

  defp filter_by_correlation_id(events, nil), do: events

  defp filter_by_correlation_id(events, correlation_id) do
    Enum.filter(events, fn event ->
      event.correlation_id == correlation_id
    end)
  end

  defp filter_by_event_type(events, nil), do: events

  defp filter_by_event_type(events, event_type) do
    Enum.filter(events, fn event ->
      event.event_type == event_type
    end)
  end

  defp filter_by_severity(events, nil), do: events

  defp filter_by_severity(events, severity) do
    Enum.filter(events, fn event ->
      event.severity == severity
    end)
  end

  defp calculate_metrics do
    all_events =
      :ets.tab2list(:audit_log_buffer)
      |> Enum.map(fn {_id, event} -> event end)

    # Count by event type
    event_counts =
      Enum.reduce(all_events, %{}, fn event, acc ->
        Map.update(acc, event.event_type, 1, &(&1 + 1))
      end)

    Map.merge(event_counts, %{
      total_events: length(all_events)
    })
  end

  defp export_events_as(:csv, criteria) do
    events = query_from_buffer(criteria)

    headers = "event_type,timestamp,severity,correlation_id,metadata\n"

    rows =
      Enum.map(events, fn event ->
        metadata_str = JSON.encode!(event.metadata) |> String.replace("\"", "'")

        "#{event.event_type},#{event.timestamp},#{event.severity},#{event.correlation_id},\"#{metadata_str}\""
      end)
      |> Enum.join("\n")

    {:ok, headers <> rows}
  end

  defp export_events_as(format, _criteria) do
    {:error, "Unsupported export format: #{format}"}
  end
end
