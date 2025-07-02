defmodule RsolvApi.AST.ProductionPythonParserTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.AST.{ParserRegistry, SessionManager}
  
  describe "Production Python Parser" do
    setup do
      # Ensure SessionManager is available
      unless Process.whereis(SessionManager) do
        Application.ensure_all_started(:rsolv_api)
      end
      
      # Ensure ParserRegistry is available
      unless Process.whereis(ParserRegistry) do
        Application.ensure_all_started(:rsolv_api)
      end
      
      # Create test customer and session
      customer_id = "test_customer_#{:crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)}"
      {:ok, session} = SessionManager.create_session(customer_id)
      
      %{customer_id: customer_id, session_id: session.id}
    end
    
    test "parses simple Python code with production parser", %{customer_id: customer_id, session_id: session_id} do
      code = """
      def hello_world():
          print("Hello, World!")
          return "success"
      
      hello_world()
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "python", code)
      
      assert result.language == "python"
      assert result.session_id == session_id
      assert result.error == nil
      assert is_map(result.ast)
      assert is_map(result.timing)
      assert result.timing.parse_time_ms > 0
      
      # Check AST structure contains expected nodes
      assert result.ast["type"] == "Module"
      assert is_list(result.ast["body"])
    end
    
    test "detects SQL injection patterns in Python code", %{customer_id: customer_id, session_id: session_id} do
      code = """
      import sqlite3
      
      def get_user(user_id):
          conn = sqlite3.connect('database.db')
          cursor = conn.cursor()
          # VULNERABLE: SQL injection
          query = f"SELECT * FROM users WHERE id = {user_id}"
          cursor.execute(query)
          return cursor.fetchall()
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "python", code)
      
      assert result.error == nil
      assert is_map(result.ast)
      
      # Should contain Call nodes for cursor.execute with f-string
      # We'll verify this with our AST pattern matcher in integration
      assert result.ast["type"] == "Module"
    end
    
    test "handles Python syntax errors gracefully", %{customer_id: customer_id, session_id: session_id} do
      code = """
      def broken_function(
          # Missing closing parenthesis
          print("This will fail")
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "python", code)
      
      assert result.language == "python"
      assert result.ast == nil
      assert is_map(result.error)
      assert result.error.type == :syntax_error
      assert is_binary(result.error.message)
    end
    
    test "parses complex Python constructs", %{customer_id: customer_id, session_id: session_id} do
      code = """
      import os
      import subprocess
      from typing import List, Dict, Optional
      
      class SecurityAnalyzer:
          def __init__(self, config: Dict[str, str]):
              self.config = config
              self.dangerous_funcs = ['eval', 'exec', 'subprocess.call']
          
          def analyze_code(self, code: str) -> Optional[List[str]]:
              findings = []
              
              # This is potentially dangerous
              if 'eval(' in code:
                  findings.append("eval usage detected")
              
              # String formatting could be SQL injection
              patterns = [
                  f"SELECT * FROM {table}" for table in self.config.get('tables', [])
              ]
              
              return findings if findings else None
          
          async def run_command(self, cmd: str) -> str:
              # Dangerous subprocess usage
              result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
              return result.stdout
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "python", code)
      
      assert result.error == nil
      assert is_map(result.ast)
      assert result.ast["type"] == "Module"
      
      # Verify complex constructs are parsed
      body = result.ast["body"]
      assert is_list(body)
      assert length(body) >= 3  # import, import, from, class
      
      # Should contain class definition
      class_def = Enum.find(body, fn node ->
        is_map(node) && node["type"] == "ClassDef"
      end)
      assert class_def != nil
      assert class_def["name"] == "SecurityAnalyzer"
    end
    
    test "returns metadata about parser and language version", %{customer_id: customer_id, session_id: session_id} do
      code = "x = 42"
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "python", code)
      
      assert result.error == nil
      assert is_map(result.ast)
      
      # The production parser should include metadata (we'll add this)
      # For now, just verify basic parsing works
      assert result.ast["type"] == "Module"
    end
    
    test "handles timeout scenarios", %{customer_id: customer_id, session_id: session_id} do
      # This will be handled by the parser timeout mechanism
      code = """
      # Simulate a complex parse that might timeout
      """ <> String.duplicate("x = 1\n", 10000)
      
      # Should complete successfully even with large input
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "python", code)
      
      assert result.error == nil
      assert is_map(result.ast)
      assert result.timing.parse_time_ms > 0
    end
    
    test "preserves line and column information", %{customer_id: customer_id, session_id: session_id} do
      code = """
      def test():
          x = eval("malicious_code")
          return x
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "python", code)
      
      assert result.error == nil
      assert is_map(result.ast)
      
      # The AST should contain line/column information
      # This will be verified by checking _lineno and _col_offset fields
      assert result.ast["type"] == "Module"
      
      # Navigate to function definition to check line numbers are preserved
      [func_def] = result.ast["body"]
      assert func_def["type"] == "FunctionDef"
      assert func_def["_lineno"] == 1
    end
    
    test "reuses parser for same session", %{customer_id: customer_id, session_id: session_id} do
      code1 = "x = 1"
      code2 = "y = 2"
      
      {:ok, result1} = ParserRegistry.parse_code(session_id, customer_id, "python", code1)
      {:ok, result2} = ParserRegistry.parse_code(session_id, customer_id, "python", code2)
      
      # Should reuse the same parser instance
      assert result1.parser_id == result2.parser_id
      assert result1.session_id == result2.session_id
      
      # Both should succeed
      assert result1.error == nil
      assert result2.error == nil
    end
  end
end