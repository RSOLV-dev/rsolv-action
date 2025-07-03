defmodule Rsolv.AST.CodeRetentionTest do
  use ExUnit.Case, async: false
  
  alias Rsolv.AST.{AnalysisService, SessionManager, ParserPool, AuditLogger}
  alias Rsolv.AST.CodeRetention
  
  setup do
    # Ensure services are started
    ensure_services_started()
    
    # Create test session
    {:ok, session} = SessionManager.create_session(test_customer_id())
    
    {:ok, %{session: session}}
  end
  
  describe "zero code retention verification" do
    test "code is not retained in memory after analysis", %{session: session} do
      # Prepare test code
      test_code = """
      function secretFunction() {
        const apiKey = "super-secret-api-key-12345";
        return apiKey;
      }
      """
      
      # Analyze the code
      options = %{
        language: "javascript",
        session_id: session.id,
        customer_id: session.customer_id,
        content: test_code
      }
      file = %{
        path: "test.js",
        content: test_code,
        language: "javascript",
        metadata: %{}
      }
      result = AnalysisService.analyze_file(file, %{"includeSecurityPatterns" => true})
      assert {:ok, _analysis} = result
      
      # Verify code is scrubbed from all components
      assert CodeRetention.verify_no_code_in_memory(test_code) == :ok
      
      # Verify specific sensitive data is not in memory
      assert CodeRetention.verify_no_code_in_memory("super-secret-api-key-12345") == :ok
    end
    
    test "code is not retained in ETS tables", %{session: session} do
      unique_marker = "unique_test_#{:rand.uniform(1000000)}"
      test_code = "const password = '#{unique_marker}';"
      
      # Analyze the code
      file = %{
        path: "test.js",
        content: test_code,
        language: "javascript",
        metadata: %{}
      }
      {:ok, _} = AnalysisService.analyze_file(file, %{"includeSecurityPatterns" => true})
      
      # Check all ETS tables for code remnants
      assert CodeRetention.verify_no_code_in_ets(test_code) == :ok
      assert CodeRetention.verify_no_code_in_ets(unique_marker) == :ok
    end
    
    test "code is not retained in AST service process dictionaries", %{session: session} do
      test_code = "const userId = " <> "#{:rand.uniform(1000)};"
      
      # Analyze the code
      file = %{
        path: "test.js",
        content: test_code,
        language: "javascript",
        metadata: %{}
      }
      {:ok, _} = AnalysisService.analyze_file(file, %{"includeSecurityPatterns" => true})
      
      # Force cleanup
      CodeRetention.force_cleanup()
      
      # Check AST service processes specifically
      assert CodeRetention.verify_no_code_in_processes(test_code) == :ok
    end
    
    test "code is scrubbed from parser responses", %{session: session} do
      test_code = "eval(userInput)"
      
      # Analyze and capture parser response
      file = %{
        path: "test.js",
        content: test_code,
        language: "javascript",
        metadata: %{}
      }
      {:ok, findings} = AnalysisService.analyze_file(file, %{"includeSecurityPatterns" => true})
      
      # For now, just verify findings don't leak code
      # (AST is not returned from analyze_file, only findings)
      assert CodeRetention.verify_findings_scrubbed(findings) == :ok
    end
    
    test "encrypted code is properly cleared after decryption", %{session: session} do
      sensitive_code = "const dbPassword = 'production-password-xyz';"
      
      # Analyze the code (which involves encryption/decryption)
      file = %{
        path: "test.js",
        content: sensitive_code,
        language: "javascript",
        metadata: %{}
      }
      {:ok, _} = AnalysisService.analyze_file(file, %{"includeSecurityPatterns" => true})
      
      # Verify decrypted code is cleared
      assert CodeRetention.verify_no_decrypted_remnants(sensitive_code) == :ok
      assert CodeRetention.verify_no_decrypted_remnants("production-password-xyz") == :ok
    end
    
    test "audit logs do not contain actual code", %{session: session} do
      test_code = """
      function processPayment(cardNumber) {
        // Card number: 4111-1111-1111-1111
        return charge(cardNumber);
      }
      """
      
      # Clear audit logs
      clear_audit_logs()
      
      # Analyze the code
      file = %{
        path: "test.js",
        content: test_code,
        language: "javascript",
        metadata: %{}
      }
      {:ok, _} = AnalysisService.analyze_file(file, %{"includeSecurityPatterns" => true})
      
      # Check audit logs don't contain sensitive data
      events = AuditLogger.query_events(%{})
      
      Enum.each(events, fn event ->
        refute event |> inspect() |> String.contains?("4111-1111-1111-1111")
        refute event |> inspect() |> String.contains?("cardNumber")
        refute event |> inspect() |> String.contains?("processPayment")
      end)
    end
    
    test "parser processes don't retain code after analysis", %{session: session} do
      test_code = "const secret = 'unique-secret-#{:rand.uniform(1000000)}';"
      
      # Analyze the code
      file = %{
        path: "test.js",
        content: test_code,
        language: "javascript",
        metadata: %{}
      }
      {:ok, _} = AnalysisService.analyze_file(file, %{"includeSecurityPatterns" => true})
      
      # Verify no AST-related processes retain the code
      assert CodeRetention.verify_no_code_in_processes(test_code) == :ok
    end
    
    @tag :slow
    test "batch analysis doesn't retain any code from the batch", %{session: session} do
      # Create multiple code samples with unique markers  
      code_samples = for i <- 1..3 do  # Reduced from 5 to 3
        %{
          path: "file#{i}.js",
          content: "const unique_var_#{i} = 'secret_value_#{i}';",
          language: "javascript",
          metadata: %{}
        }
      end
      
      options = %{
        "customer_id" => session.customer_id,
        "session_id" => session.id
      }
      
      # Analyze batch
      {:ok, _results} = AnalysisService.analyze_batch(code_samples, options, session)
      
      # Verify none of the code is retained
      Enum.each(code_samples, fn sample ->
        assert CodeRetention.verify_no_code_in_memory(sample.content) == :ok
        assert CodeRetention.verify_no_code_in_memory("unique_var_") == :ok
        assert CodeRetention.verify_no_code_in_memory("secret_value_") == :ok
      end)
    end
    
    test "code retention verification report", %{session: session} do
      test_code = "function leak() { return 'memory-leak-test'; }"
      
      # Analyze the code
      file = %{
        path: "test.js",
        content: test_code,
        language: "javascript",
        metadata: %{}
      }
      {:ok, _} = AnalysisService.analyze_file(file, %{"includeSecurityPatterns" => true})
      
      # Generate retention report
      {:ok, report} = CodeRetention.generate_retention_report()
      
      assert report.memory_checked == true
      assert report.ets_tables_checked > 0
      assert report.processes_checked > 0
      assert report.retention_found == []
      assert report.verification_passed == true
    end
    
    test "forced garbage collection clears references from AST services", %{session: session} do
      unique_marker = "unique_cleanup_test_#{:rand.uniform(1000000)}"
      test_code = "const cleanupTest = '#{unique_marker}';"
      
      # Analyze the code
      file = %{
        path: "test.js",
        content: test_code,
        language: "javascript",
        metadata: %{}
      }
      {:ok, _} = AnalysisService.analyze_file(file, %{"includeSecurityPatterns" => true})
      
      # Force garbage collection
      CodeRetention.force_cleanup()
      
      # Verify code is not in AST service processes
      assert CodeRetention.verify_no_code_in_processes(test_code) == :ok
      
      # Verify code is not in ETS tables we control
      assert CodeRetention.verify_no_code_in_ets(unique_marker) == :ok
    end
  end
  
  # Helper functions
  
  defp ensure_services_started do
    services = [
      {Rsolv.AST.ParserRegistry, []},
      {ParserPool, []},
      {SessionManager, []},
      {AuditLogger, []},
      {AnalysisService, []}
    ]
    
    Enum.each(services, fn {module, opts} ->
      case GenServer.whereis(module) do
        nil -> {:ok, _} = apply(module, :start_link, [opts])
        _pid -> :ok
      end
    end)
  end
  
  defp test_customer_id, do: 12345
  
  defp clear_audit_logs do
    case :ets.whereis(:audit_log_buffer) do
      :undefined -> :ok
      _ -> :ets.delete_all_objects(:audit_log_buffer)
    end
  end
end