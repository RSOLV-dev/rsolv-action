defmodule Rsolv.AST.AuditLoggerTest do
  # Can be async with proper test design
  use Rsolv.IntegrationCase

  alias Rsolv.AST.AuditLogger

  setup do
    # Check if AuditLogger is already running (from application supervision tree)
    case Process.whereis(Rsolv.AST.AuditLogger) do
      nil ->
        # Not running, start it under test supervision
        {:ok, _pid} = start_supervised(Rsolv.AST.AuditLogger)

      _pid ->
        # Already running from application, just use it
        :ok
    end

    # Clear the in-memory buffer for test isolation
    # This is a synchronous call that returns when complete
    AuditLogger.clear_buffer()

    # Clean up any existing audit tables for test isolation
    case :ets.whereis(:audit_log_buffer) do
      :undefined -> :ok
      table -> :ets.delete_all_objects(table)
    end

    case :ets.whereis(:audit_log_index) do
      :undefined -> :ok
      table -> :ets.delete_all_objects(table)
    end

    {:ok, %{}}
  end

  describe "audit event logging" do
    test "logs parser spawn events with structured format" do
      event =
        AuditLogger.log_event(:parser_spawned, %{
          session_id: "test-session-123",
          language: "javascript",
          file_path: "/app/src/index.js",
          file_size: 1024,
          customer_id: 42
        })

      assert event.id != nil
      assert event.timestamp != nil
      assert event.event_type == :parser_spawned
      assert event.severity == :info
      assert event.metadata.session_id == "test-session-123"
      assert event.correlation_id != nil
    end

    test "logs security violations with high severity" do
      event =
        AuditLogger.log_event(:malicious_input_detected, %{
          session_id: "test-session-456",
          language: "python",
          pattern: ~r/__import__/,
          input_preview: "__import__('os').system('rm -rf /')",
          customer_id: 99
        })

      assert event.event_type == :malicious_input_detected
      assert event.severity == :critical
      assert event.metadata.pattern != nil
    end

    test "logs rate limit violations" do
      event =
        AuditLogger.log_event(:rate_limit_exceeded, %{
          language: "ruby",
          customer_id: 123,
          requests_per_minute: 150,
          limit: 100
        })

      assert event.event_type == :rate_limit_exceeded
      assert event.severity == :warning
      assert event.metadata.requests_per_minute == 150
    end

    test "generates correlation IDs for related events" do
      correlation_id = AuditLogger.generate_correlation_id()

      event1 =
        AuditLogger.log_event(
          :session_created,
          %{
            customer_id: 1
          },
          correlation_id: correlation_id
        )

      event2 =
        AuditLogger.log_event(
          :file_encrypted,
          %{
            session_id: "abc",
            file_path: "test.js"
          },
          correlation_id: correlation_id
        )

      assert event1.correlation_id == event2.correlation_id
      assert event1.correlation_id == correlation_id
    end

    test "automatically assigns severity levels" do
      info_event = AuditLogger.log_event(:parser_spawned, %{})
      assert info_event.severity == :info

      warning_event = AuditLogger.log_event(:parser_timeout, %{})
      assert warning_event.severity == :warning

      error_event = AuditLogger.log_event(:parser_crashed, %{})
      assert error_event.severity == :error

      critical_event = AuditLogger.log_event(:code_exfiltration_attempt, %{})
      assert critical_event.severity == :critical
    end
  end

  describe "persistent storage" do
    setup do
      # Ensure clean state for storage tests
      AuditLogger.clear_buffer()
      :ok
    end

    test "buffers events for batch persistence" do
      # Log multiple events
      for i <- 1..5 do
        AuditLogger.log_event(:test_event, %{index: i})
      end

      # Check buffer
      buffered = AuditLogger.get_buffer()
      assert length(buffered) == 5
    end

    test "flushes buffer to persistent storage" do
      # Generate unique test data to track our specific events
      unique_id = System.unique_integer([:positive])
      test1_value = "test1_#{unique_id}"
      test2_value = "test2_#{unique_id}"
      event1_data = %{data: test1_value}
      event2_data = %{data: test2_value}

      # Log our specific events
      AuditLogger.log_event(:test_event, event1_data)
      AuditLogger.log_event(:test_event, event2_data)

      # Verify our events are in the buffer (don't care about exact count)
      buffer_before = AuditLogger.get_buffer()

      our_events =
        Enum.filter(buffer_before, fn event ->
          case event do
            %{metadata: %{data: data}} when data in [test1_value, test2_value] -> true
            _ -> false
          end
        end)

      assert length(our_events) == 2, "Our two events should be in the buffer"

      # Flush to storage
      {:ok, count} = AuditLogger.flush_to_storage()
      assert count > 0, "Should flush at least some events"

      # Verify our events are no longer in buffer
      buffer_after = AuditLogger.get_buffer()

      our_events_after =
        Enum.filter(buffer_after, fn event ->
          case event do
            %{metadata: %{data: data}} when data in [test1_value, test2_value] -> true
            _ -> false
          end
        end)

      assert length(our_events_after) == 0, "Our events should be flushed"
    end

    test "handles storage failures gracefully" do
      # Simulate storage failure
      AuditLogger.set_storage_backend({:error, :database_down})

      # Ensure we reset to default backend after test
      on_exit(fn -> AuditLogger.set_storage_backend(:ets) end)

      AuditLogger.log_event(:test_event, %{})

      # Should still buffer events
      assert length(AuditLogger.get_buffer()) == 1

      # Flush should fail but not crash
      {:error, reason} = AuditLogger.flush_to_storage()
      assert reason == :database_down
    end
  end

  describe "structured format" do
    test "formats events as JSON-compatible maps" do
      event =
        AuditLogger.log_event(:test_event, %{
          string: "hello",
          number: 42,
          atom: :test,
          list: [1, 2, 3]
        })

      # Should be JSON-serializable
      json = JSON.encode!(event)
      decoded = JSON.decode!(json)

      assert decoded["event_type"] == "test_event"
      assert decoded["metadata"]["string"] == "hello"
      assert decoded["metadata"]["number"] == 42
    end

    test "includes standard fields in all events" do
      event = AuditLogger.log_event(:any_event, %{})

      assert Map.has_key?(event, :id)
      assert Map.has_key?(event, :timestamp)
      assert Map.has_key?(event, :event_type)
      assert Map.has_key?(event, :severity)
      assert Map.has_key?(event, :correlation_id)
      assert Map.has_key?(event, :metadata)
      assert Map.has_key?(event, :node)
      assert Map.has_key?(event, :version)
    end

    test "sanitizes sensitive data" do
      event =
        AuditLogger.log_event(:api_call, %{
          api_key: "sk-1234567890abcdef",
          password: "supersecret",
          credit_card: "4111111111111111",
          safe_field: "this is fine"
        })

      assert event.metadata.api_key == "[REDACTED]"
      assert event.metadata.password == "[REDACTED]"
      assert event.metadata.credit_card == "[REDACTED]"
      assert event.metadata.safe_field == "this is fine"
    end
  end

  describe "query and analysis" do
    test "queries events by time range" do
      # Log events at different times
      old_event =
        AuditLogger.log_event(:old_event, %{},
          timestamp: DateTime.add(DateTime.utc_now(), -3600, :second)
        )

      recent_event = AuditLogger.log_event(:recent_event, %{})

      # Query last hour
      events =
        AuditLogger.query_events(%{
          since: DateTime.add(DateTime.utc_now(), -1800, :second)
        })

      assert length(events) == 1
      assert hd(events).event_type == :recent_event
    end

    test "queries events by correlation ID" do
      corr_id = AuditLogger.generate_correlation_id()

      AuditLogger.log_event(:event1, %{}, correlation_id: corr_id)
      AuditLogger.log_event(:event2, %{}, correlation_id: corr_id)
      AuditLogger.log_event(:unrelated, %{})

      events = AuditLogger.query_events(%{correlation_id: corr_id})
      assert length(events) == 2
    end

    test "aggregates security metrics" do
      # Log various security events
      AuditLogger.log_event(:malicious_input_detected, %{language: "js"})
      AuditLogger.log_event(:malicious_input_detected, %{language: "py"})
      AuditLogger.log_event(:rate_limit_exceeded, %{customer_id: 1})
      AuditLogger.log_event(:parser_spawned, %{})

      metrics = AuditLogger.get_security_metrics()

      assert metrics.malicious_input_detected == 2
      assert metrics.rate_limit_exceeded == 1
      assert metrics.total_events >= 4
    end
  end

  describe "integration with existing components" do
    test "integrates with EnhancedSandbox logging" do
      # This will be called by EnhancedSandbox
      event =
        AuditLogger.log_security_event(:parser_spawned, %{
          language: "javascript",
          input_size: 1024,
          sanitized: false
        })

      assert event.event_type == :parser_spawned
      assert event.metadata.category == :security
    end

    test "tracks session lifecycle" do
      session_id = "test-session-789"
      corr_id = AuditLogger.generate_correlation_id()

      # Session lifecycle events
      AuditLogger.log_event(:session_created, %{session_id: session_id}, correlation_id: corr_id)
      AuditLogger.log_event(:file_encrypted, %{session_id: session_id}, correlation_id: corr_id)
      AuditLogger.log_event(:ast_parsed, %{session_id: session_id}, correlation_id: corr_id)
      AuditLogger.log_event(:session_cleaned, %{session_id: session_id}, correlation_id: corr_id)

      # Should be able to reconstruct session timeline
      events = AuditLogger.query_events(%{correlation_id: corr_id})
      assert length(events) == 4

      event_types = Enum.map(events, & &1.event_type)
      assert :session_created in event_types
      assert :session_cleaned in event_types
    end
  end

  describe "compliance and retention" do
    test "supports configurable retention policies" do
      # Configure 7-day retention
      AuditLogger.configure_retention(%{
        max_age_days: 7,
        max_events: 1_000_000
      })

      config = AuditLogger.get_retention_config()
      assert config.max_age_days == 7
      assert config.max_events == 1_000_000
    end

    test "exports events for compliance reporting" do
      # Log some events
      AuditLogger.log_event(:test1, %{data: "value1"})
      AuditLogger.log_event(:test2, %{data: "value2"})

      # Export as CSV
      {:ok, csv} =
        AuditLogger.export_events(:csv, %{
          since: DateTime.add(DateTime.utc_now(), -3600, :second)
        })

      assert String.contains?(csv, "test1")
      assert String.contains?(csv, "test2")
      assert String.contains?(csv, "event_type,timestamp,severity")
    end
  end
end
