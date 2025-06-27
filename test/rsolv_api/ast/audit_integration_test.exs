defmodule RsolvApi.AST.AuditIntegrationTest do
  use ExUnit.Case, async: false
  
  alias RsolvApi.AST.{AuditLogger, EnhancedSandbox}
  
  setup do
    # Ensure AuditLogger is started fresh for each test
    case GenServer.whereis(AuditLogger) do
      nil -> 
        {:ok, _} = AuditLogger.start_link()
      pid when is_pid(pid) ->
        # Stop and restart to ensure clean state
        GenServer.stop(pid)
        Process.sleep(10)
        {:ok, _} = AuditLogger.start_link()
    end
    
    # Give GenServer time to initialize
    Process.sleep(10)
    
    # Clear any existing tables
    for table <- [:audit_log_buffer, :audit_log_index, :security_events] do
      case :ets.whereis(table) do
        :undefined -> :ok
        _ -> :ets.delete_all_objects(table)
      end
    end
    
    {:ok, %{}}
  end
  
  describe "security event audit trail" do
    test "tracks malicious input detection through full lifecycle" do
      # Simulate malicious input detection
      malicious_code = """
      import os
      __import__('subprocess').call(['rm', '-rf', '/'])
      """
      
      # This should trigger validation failure and logging
      {:error, {:suspicious_pattern, _}} = 
        EnhancedSandbox.validate_input(malicious_code, "python")
      
      # Query audit logs
      events = AuditLogger.query_events(%{
        event_type: :input_validation_failed
      })
      
      assert length(events) == 1
      event = hd(events)
      
      assert event.event_type == :input_validation_failed
      assert event.severity == :info  # Currently mapped as info
      assert event.metadata.language == "python"
      assert event.metadata.reason == {:suspicious_pattern, ~r/__import__/}
      assert String.contains?(event.metadata.input_preview, "__import__")
    end
    
    test "tracks rate limiting violations" do
      # Clear rate limit table
      case :ets.whereis(:parser_rate_limits) do
        :undefined -> :ok
        table -> :ets.delete_all_objects(table)
      end
      
      config = EnhancedSandbox.create_enhanced_config("javascript")
      
      # Hit rate limit
      for _ <- 1..101 do
        EnhancedSandbox.check_rate_limit(config)
      end
      
      # Query rate limit events
      events = AuditLogger.query_events(%{
        event_type: :rate_limit_exceeded
      })
      
      assert length(events) >= 1
      event = hd(events)
      
      assert event.event_type == :rate_limit_exceeded
      assert event.severity == :warning
      assert event.metadata.language == "javascript"
    end
    
    test "generates security metrics report" do
      # Generate various security events
      EnhancedSandbox.validate_input("eval(userInput)", "javascript")
      EnhancedSandbox.validate_input("__import__('os')", "python")
      EnhancedSandbox.validate_input("normal code", "ruby")
      
      # Get metrics
      metrics = AuditLogger.get_security_metrics()
      
      assert metrics.input_validation_failed >= 2
      assert metrics.total_events >= 3
    end
    
    test "exports compliance report" do
      # Generate some events
      corr_id = AuditLogger.generate_correlation_id()
      
      AuditLogger.log_event(:session_created, %{
        customer_id: 123,
        session_id: "test-session"
      }, correlation_id: corr_id)
      
      AuditLogger.log_event(:malicious_input_detected, %{
        language: "javascript",
        pattern: "eval",
        customer_id: 123
      }, correlation_id: corr_id)
      
      # Export as CSV
      {:ok, csv} = AuditLogger.export_events(:csv, %{
        correlation_id: corr_id
      })
      
      assert String.contains?(csv, "event_type,timestamp,severity")
      assert String.contains?(csv, "session_created")
      assert String.contains?(csv, "malicious_input_detected")
      assert String.contains?(csv, corr_id)
    end
  end
end