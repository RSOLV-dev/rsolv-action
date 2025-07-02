defmodule RsolvApi.AST.ParserRegistryTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.AST.ParserRegistry
  alias RsolvApi.AST.SessionManager
  
  setup do
    # SessionManager and ParserRegistry should already be started by application
    # Just ensure they're running
    case GenServer.whereis(SessionManager) do
      _ -> :ok
    end
    
    case GenServer.whereis(ParserRegistry) do
      nil -> :ok  # ParserRegistry is started by Application
      _ -> :ok
    end
    
    :ok
  end
  
  describe "parser registration" do
    test "registers supported language parsers" do
      # Should have default parsers registered
      parsers = ParserRegistry.list_parsers()
      
      assert is_list(parsers)
      assert length(parsers) > 0
      
      # Check for expected languages
      languages = Enum.map(parsers, & &1.language)
      assert "javascript" in languages
      assert "python" in languages
    end
    
    test "gets parser configuration by language" do
      {:ok, js_parser} = ParserRegistry.get_parser("javascript")
      
      assert js_parser.language == "javascript"
      assert js_parser.command != nil
      assert js_parser.args != nil
      assert is_list(js_parser.extensions)
      assert ".js" in js_parser.extensions
    end
    
    test "returns error for unsupported language" do
      assert {:error, :parser_not_found} = ParserRegistry.get_parser("unsupported")
    end
  end
  
  describe "parser routing" do
    test "routes request to appropriate parser" do
      customer_id = "test-customer"
      {:ok, session} = SessionManager.create_session(customer_id)
      
      code = "function test() { return 42; }"
      
      {:ok, result} = ParserRegistry.parse_code(session.id, customer_id, "javascript", code)
      
      assert result.language == "javascript"
      assert result.ast != nil
      assert result.session_id == session.id
    end
    
    test "handles parsing errors gracefully" do
      customer_id = "test-customer"
      {:ok, session} = SessionManager.create_session(customer_id)
      
      invalid_code = "function test( { invalid syntax"
      
      {:ok, result} = ParserRegistry.parse_code(session.id, customer_id, "javascript", invalid_code)
      
      assert result.language == "javascript"
      assert result.error != nil
      assert result.ast == nil
    end
    
    test "rejects invalid session" do
      invalid_session = "invalid-session-id"
      customer_id = "test-customer"
      code = "function test() { return 42; }"
      
      assert {:error, :invalid_session} = 
        ParserRegistry.parse_code(invalid_session, customer_id, "javascript", code)
    end
  end
  
  describe "parser lifecycle" do
    test "starts parser on demand" do
      customer_id = "test-customer"
      {:ok, session} = SessionManager.create_session(customer_id)
      
      # First request should start parser
      code = "def test(): return 42"
      {:ok, result} = ParserRegistry.parse_code(session.id, customer_id, "python", code)
      
      assert result.language == "python"
      
      # Verify parser is running
      {:ok, parser_info} = ParserRegistry.get_parser_status("python", session.id)
      assert parser_info.status == :running
    end
    
    @tag :integration
    test "reuses existing parser for same session" do
      customer_id = "test-customer"
      {:ok, session} = SessionManager.create_session(customer_id)
      
      code1 = "function test1() { return 1; }"
      code2 = "function test2() { return 2; }"
      
      {:ok, result1} = ParserRegistry.parse_code(session.id, customer_id, "javascript", code1)
      {:ok, result2} = ParserRegistry.parse_code(session.id, customer_id, "javascript", code2)
      
      # Should use same parser instance
      assert result1.parser_id == result2.parser_id
    end
    
    @tag :integration
    test "isolates parsers between different sessions" do
      customer_id = "test-customer"
      {:ok, session1} = SessionManager.create_session(customer_id)
      {:ok, session2} = SessionManager.create_session(customer_id)
      
      code = "function test() { return 42; }"
      
      {:ok, result1} = ParserRegistry.parse_code(session1.id, customer_id, "javascript", code)
      {:ok, result2} = ParserRegistry.parse_code(session2.id, customer_id, "javascript", code)
      
      # Should use different parser instances
      assert result1.parser_id != result2.parser_id
    end
  end
  
  describe "error handling" do
    test "handles parser crash gracefully" do
      customer_id = "test-customer"
      {:ok, session} = SessionManager.create_session(customer_id)
      
      # This should cause parser to crash but be restarted
      crash_code = "FORCE_CRASH_SIGNAL"
      
      {:ok, result} = ParserRegistry.parse_code(session.id, customer_id, "javascript", crash_code)
      
      assert result.error != nil
      assert is_map(result.error)
      assert result.error.type == :parser_crash
      assert result.error.message =~ "crash"
      
      # Next request should work (parser restarted)
      normal_code = "function test() { return 42; }"
      {:ok, result2} = ParserRegistry.parse_code(session.id, customer_id, "javascript", normal_code)
      
      assert result2.ast != nil
    end
    
    test "enforces parser timeout" do
      customer_id = "test-customer"
      {:ok, session} = SessionManager.create_session(customer_id)
      
      # This should timeout
      timeout_code = "FORCE_TIMEOUT_SIGNAL"
      
      {:ok, result} = ParserRegistry.parse_code(session.id, customer_id, "javascript", timeout_code)
      
      assert result.error != nil
      assert is_map(result.error)
      assert result.error.type == :timeout
      assert result.error.message =~ "timeout"
    end
  end
  
  describe "performance monitoring" do
    test "tracks parser performance metrics" do
      customer_id = "test-customer"
      {:ok, session} = SessionManager.create_session(customer_id)
      
      code = "function test() { return 42; }"
      {:ok, result} = ParserRegistry.parse_code(session.id, customer_id, "javascript", code)
      
      assert result.timing != nil
      assert result.timing.parse_time_ms > 0
      assert result.timing.total_time_ms > 0
    end
    
    test "provides parser statistics" do
      stats = ParserRegistry.get_statistics()
      
      assert stats.total_requests >= 0
      assert stats.active_parsers >= 0
      assert stats.success_rate >= 0.0
      assert stats.success_rate <= 1.0
    end
  end
end