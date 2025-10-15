defmodule Rsolv.AST.EnhancedSandbox do
  @moduledoc """
  Enhanced BEAM-native sandboxing for MVP/Beta security.

  Adds to existing Sandbox module:
  - Input validation and sanitization
  - Pattern-based malicious input detection
  - Enhanced spawn options
  - Stricter environment controls
  - Process priority management
  """

  require Logger
  alias Rsolv.AST.{Sandbox, AuditLogger}

  # Suspicious patterns that might indicate malicious input - using function instead of module attribute
  defp suspicious_patterns do
    [
      # Zip bombs and recursive includes
      ~r/\.zip\s*\(/i,
      ~r/require\s*\(\s*require/i,
      ~r/import\s*\(\s*import/i,

      # Shell injection attempts
      ~r/\$\(.*\)/,
      ~r/`.*`/,
      ~r/\bexec\s*\(/,
      ~r/\bsystem\s*\(/,
      ~r/\beval\s*\(/,

      # Path traversal
      ~r/\.\.[\/\\]/,
      ~r/\/etc\//,
      ~r/\/proc\//,

      # Network attempts
      ~r/\b(http|https|ftp):\/\//i,
      ~r/\b(fetch|axios|request)\s*\(/i,

      # Excessive nesting/complexity
      # More than 50 nested brackets
      ~r/(\{|\[){50,}/
    ]
  end

  # Complexity score limit
  @max_input_complexity 5_000
  # @max_nesting_depth 50         # Maximum AST nesting (reserved for future use)

  @doc """
  Validates and sanitizes parser input before processing.
  Returns {:ok, sanitized_input} or {:error, reason}
  """
  def validate_input(input, language) when is_binary(input) do
    with :ok <- check_size_limits(input),
         :ok <- check_suspicious_patterns(input, language),
         :ok <- check_complexity(input),
         {:ok, sanitized} <- sanitize_input(input, language) do
      {:ok, sanitized}
    end
  end

  @doc """
  Creates enhanced sandbox configuration with stricter limits.
  """
  def create_enhanced_config(parser_type, options \\ %{}) do
    base_config = Sandbox.create_beam_sandbox_config(parser_type, options)

    enhanced_limits =
      Map.merge(base_config.limits, %{
        # Stricter memory limits for MVP
        # 128MB (was 256MB)
        max_heap_size: 32_000_000,
        # Half the CPU time
        max_reductions: 1_000_000,
        # 15 seconds (was 30)
        timeout_ms: 15_000,
        # Prevent message flooding
        max_message_queue: 100,
        # Limit subprocess spawning
        max_processes: 10
      })

    enhanced_spawn_opts =
      base_config.spawn_opts ++
        [
          # Lower priority than main app
          priority: :low,
          # Start small
          min_heap_size: 233,
          # Binary heap control
          min_bin_vheap_size: 46422,
          # Aggressive GC
          fullsweep_after: 10
        ]

    Map.merge(base_config, %{
      limits: enhanced_limits,
      spawn_opts: enhanced_spawn_opts,
      strict_mode: true
    })
  end

  @doc """
  Spawns parser with enhanced security checks.
  """
  def spawn_enhanced_parser(config, command, args, input) do
    # Pre-flight validation
    language = config.type

    case validate_input(input, language) do
      {:ok, sanitized_input} ->
        # Add rate limiting check
        case check_rate_limit(config) do
          :ok ->
            # Spawn with enhanced config
            result = Sandbox.spawn_sandboxed_port(config, command, args)

            # Log for audit trail
            log_security_event(:parser_spawned, %{
              language: language,
              input_size: byte_size(input),
              sanitized: sanitized_input != input
            })

            result

          {:error, :rate_limited} ->
            log_security_event(:rate_limit_exceeded, %{language: language})
            {:error, :rate_limited}
        end

      {:error, reason} = error ->
        log_security_event(:input_validation_failed, %{
          language: language,
          reason: reason,
          input_preview: String.slice(input, 0, 100)
        })

        error
    end
  end

  # Private validation functions

  defp check_size_limits(input) do
    cond do
      byte_size(input) > 10 * 1024 * 1024 ->
        {:error, :file_too_large}

      byte_size(input) == 0 ->
        {:error, :empty_input}

      true ->
        :ok
    end
  end

  defp check_suspicious_patterns(input, language) do
    # Get base patterns
    base_patterns = get_base_suspicious_patterns()

    # Add language-specific patterns
    patterns =
      case language do
        "javascript" -> base_patterns ++ [~r/new\s+Function\s*\(/]
        "python" -> base_patterns ++ [~r/__import__/, ~r/compile\s*\(/]
        "ruby" -> base_patterns ++ [~r/\bsend\s*\(/, ~r/instance_eval/]
        "php" -> base_patterns ++ [~r/\bshell_exec/, ~r/\bpassthru/]
        _ -> base_patterns
      end

    case Enum.find(patterns, fn pattern -> Regex.match?(pattern, input) end) do
      nil ->
        :ok

      pattern ->
        Logger.warning("Suspicious pattern detected: #{inspect(pattern)}")
        # Log to AuditLogger for audit trail
        AuditLogger.log_event(:input_validation_failed, %{
          language: language,
          reason: {:suspicious_pattern, pattern},
          input_preview: String.slice(input, 0, 100)
        })

        {:error, {:suspicious_pattern, pattern}}
    end
  end

  defp get_base_suspicious_patterns do
    suspicious_patterns()
  end

  defp check_complexity(input) do
    # Simple complexity scoring
    complexity = calculate_complexity_score(input)

    if complexity > @max_input_complexity do
      {:error, {:complexity_too_high, complexity}}
    else
      :ok
    end
  end

  defp calculate_complexity_score(input) do
    # Count various complexity indicators
    bracket_depth = calculate_max_nesting(input)
    unique_chars = input |> String.graphemes() |> Enum.uniq() |> length()

    # Simple heuristic
    byte_size(input) * 0.1 + bracket_depth * 100 + (1000 - unique_chars)
  end

  defp calculate_max_nesting(input) do
    input
    |> String.graphemes()
    |> Enum.reduce({0, 0}, fn char, {current, max} ->
      case char do
        c when c in ["{", "[", "("] ->
          new_depth = current + 1
          {new_depth, max(new_depth, max)}

        c when c in ["}", "]", ")"] ->
          {max(current - 1, 0), max}

        _ ->
          {current, max}
      end
    end)
    |> elem(1)
  end

  defp sanitize_input(input, _language) do
    # Basic sanitization
    sanitized =
      input
      # Remove null bytes
      |> String.replace(~r/\0/, "")
      # Enforce max size
      |> String.slice(0, 10 * 1024 * 1024)

    {:ok, sanitized}
  end

  def check_rate_limit(config) do
    # Simple in-memory rate limiting
    # In production, this would use Redis/Mnesia
    key = {:rate_limit, config.type}

    case :ets.whereis(:parser_rate_limits) do
      :undefined ->
        :ets.new(:parser_rate_limits, [:named_table, :public])
        safe_ets_insert(:parser_rate_limits, {key, 1, System.system_time(:second)})
        :ok

      _table ->
        now = System.system_time(:second)

        case :ets.lookup(:parser_rate_limits, key) do
          [{^key, count, timestamp}] when now - timestamp < 60 ->
            # Same minute
            # 100 requests per minute
            if count >= 100 do
              AuditLogger.log_event(:rate_limit_exceeded, %{
                language: config.type,
                count: count,
                timestamp: timestamp
              })

              {:error, :rate_limited}
            else
              safe_ets_update_counter(:parser_rate_limits, key, {2, 1})
              :ok
            end

          _ ->
            # New minute
            safe_ets_insert(:parser_rate_limits, {key, 1, now})
            :ok
        end
    end
  end

  defp log_security_event(event_type, metadata) do
    # In production, this would go to a proper audit log
    Logger.info("SECURITY_EVENT: #{event_type}", metadata)

    # Also track in ETS for monitoring
    case :ets.whereis(:security_events) do
      :undefined ->
        :ets.new(:security_events, [:named_table, :public, :ordered_set])

      _ ->
        :ok
    end

    safe_ets_insert(:security_events, {
      {System.system_time(:nanosecond), event_type},
      metadata
    })
  end

  @doc """
  Get security metrics for monitoring.
  """
  def get_security_metrics() do
    events =
      case :ets.whereis(:security_events) do
        :undefined -> []
        _ -> :ets.tab2list(:security_events)
      end

    # Group by event type
    events
    |> Enum.group_by(fn {{_time, type}, _meta} -> type end)
    |> Enum.map(fn {type, items} -> {type, length(items)} end)
    |> Map.new()
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

  defp safe_ets_update_counter(table, key, increment) do
    try do
      :ets.update_counter(table, key, increment)
    catch
      # Table doesn't exist, ignore gracefully
      :error, :badarg -> :ok
    end
  end
end
