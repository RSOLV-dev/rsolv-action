defmodule RsolvApi.AST.PortPocTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.AST.PortPoc
  
  describe "Port communication proof of concept" do
    test "echo test works" do
      {:ok, result} = PortPoc.test_echo()
      
      assert result["status"] == "success"
      assert result["echo"]["action"] == "parse"
      assert result["echo"]["code"] == "def hello(): pass"
    end
    
    test "Python parser integration" do
      results = PortPoc.test_python_parser()
      
      # First test - valid Python code
      [first, second, third] = results
      
      assert first["status"] == "success"
      assert first["id"] == "1"
      assert first["ast"]["_type"] == "Module"
      assert is_integer(first["metadata"]["parse_time_ms"])
      
      # Second test - syntax error
      assert second["status"] == "error"
      assert second["id"] == "2"
      assert second["error"]["type"] == "SyntaxError"
      
      # Third test - invalid action
      assert third["status"] == "error"
      assert third["id"] == "3"
      assert third["error"]["type"] == "InvalidAction"
    end
    
    @tag :skip
    test "Ruby parser integration" do
      # Skipping for now - will implement after Python works
      assert true
    end
  end
end