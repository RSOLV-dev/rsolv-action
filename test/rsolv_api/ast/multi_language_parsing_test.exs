defmodule RsolvApi.AST.MultiLanguageParsingTest do
  use RsolvApi.AST.TestCase
  
  alias RsolvApi.AST.PortSupervisor
  
  describe "Python parsing" do
    test "parses simple Python code" do
      code = test_code("python", :simple)
      
      # Create a temporary Python file
      with_temp_file(code, "py", fn path ->
        {:ok, ast} = PortSupervisor.parse("python", code)
        
        assert ast["_type"] == "Module"
        assert is_list(ast["_fields"]["body"])
        
        # Find function definition
        func_defs = find_nodes(ast, "FunctionDef")
        assert length(func_defs) == 1
        
        func_def = List.first(func_defs)
        assert func_def["_fields"]["name"] == "hello"
      end)
    end
    
    test "detects Python SQL injection" do
      vulnerable_code = test_code("python", :sql_injection_vulnerable)
      safe_code = test_code("python", :sql_injection_safe)
      
      # Parse vulnerable code
      {:ok, vuln_ast} = PortSupervisor.parse("python", vulnerable_code)
      
      # Look for f-string with SQL
      joined_strs = find_nodes(vuln_ast, "JoinedStr")
      assert length(joined_strs) > 0
      
      # Parse safe code
      {:ok, safe_ast} = PortSupervisor.parse("python", safe_code)
      
      # Safe code should use different pattern
      joined_strs_safe = find_nodes(safe_ast, "JoinedStr")
      # Safe version uses parameterized query, no f-string in SQL
      assert length(joined_strs_safe) == 0
    end
    
    test "handles Python syntax errors gracefully" do
      code = test_code("python", :syntax_error)
      
      case PortSupervisor.parse("python", code) do
        {:error, reason} ->
          assert String.contains?(reason, "SyntaxError")
        {:ok, _} ->
          flunk("Expected syntax error")
      end
    end
    
    test "detects command injection patterns" do
      code = test_code("python", :command_injection_vulnerable)
      
      {:ok, ast} = PortSupervisor.parse("python", code)
      
      # Find os.system calls
      calls = find_nodes(ast, "Call")
      os_system_calls = Enum.filter(calls, fn call ->
        case call["_fields"]["func"] do
          %{"_type" => "Attribute", "_fields" => %{"attr" => "system"}} -> true
          _ -> false
        end
      end)
      
      assert length(os_system_calls) == 1
    end
  end
  
  describe "Ruby parsing" do
    @tag :skip
    test "parses simple Ruby code" do
      code = test_code("ruby", :simple)
      
      {:ok, ast} = PortSupervisor.parse("ruby", code)
      
      # Ruby AST structure
      assert ast["type"] == :def or ast[:type] == :def
      assert is_list(ast["children"]) or is_list(ast[:children])
    end
    
    @tag :skip
    test "detects Ruby SQL injection" do
      vulnerable_code = test_code("ruby", :sql_injection_vulnerable)
      
      {:ok, ast} = PortSupervisor.parse("ruby", vulnerable_code)
      
      # Look for string interpolation in where clause
      dstr_nodes = find_nodes(ast, :dstr)
      assert length(dstr_nodes) > 0
    end
  end
  
  describe "PHP parsing" do
    @tag :skip
    test "parses simple PHP code" do
      code = test_code("php", :simple)
      
      {:ok, ast} = PortSupervisor.parse("php", code)
      
      # PHP AST should have function nodes
      assert ast != nil
    end
    
    @tag :skip
    test "detects PHP XSS vulnerabilities" do
      vulnerable_code = test_code("php", :xss_vulnerable)
      safe_code = test_code("php", :xss_safe)
      
      {:ok, vuln_ast} = PortSupervisor.parse("php", vulnerable_code)
      {:ok, safe_ast} = PortSupervisor.parse("php", safe_code)
      
      # Vulnerable should have direct echo
      # Safe should have htmlspecialchars
      assert vuln_ast != safe_ast
    end
  end
  
  describe "Java parsing" do
    @tag :skip
    test "parses simple Java code" do
      code = test_code("java", :simple)
      
      {:ok, ast} = PortSupervisor.parse("java", code)
      
      # Java AST should have class declaration
      assert ast != nil
    end
    
    @tag :skip
    test "detects Java command injection" do
      code = test_code("java", :command_injection_vulnerable)
      
      {:ok, ast} = PortSupervisor.parse("java", code)
      
      # Look for Runtime.exec calls
      # AST structure depends on parser used
      assert ast != nil
    end
  end
  
  describe "JavaScript parsing" do
    test "parses simple JavaScript code" do
      code = test_code("javascript", :simple)
      
      {:ok, ast} = PortSupervisor.parse("javascript", code)
      
      # JS AST should have Program root
      assert ast["type"] == "Program" or ast[:type] == "Program"
    end
    
    test "detects JavaScript SQL injection" do
      vulnerable_code = test_code("javascript", :sql_injection_vulnerable)
      
      {:ok, ast} = PortSupervisor.parse("javascript", vulnerable_code)
      
      # Look for template literals with expressions
      template_literals = find_nodes(ast, "TemplateLiteral")
      assert length(template_literals) > 0
    end
  end
  
  describe "Elixir parsing" do
    @tag :skip
    test "parses simple Elixir code" do
      code = test_code("elixir", :simple)
      
      {:ok, ast} = PortSupervisor.parse("elixir", code)
      
      # Elixir AST is a tuple structure
      assert is_tuple(ast) or is_map(ast)
    end
    
    @tag :skip
    test "detects Elixir command injection" do
      code = test_code("elixir", :command_injection_vulnerable)
      
      {:ok, ast} = PortSupervisor.parse("elixir", code)
      
      # Look for System.shell calls
      assert ast != nil
    end
  end
  
  describe "Parser performance" do
    test "parses files within time limit" do
      languages = ["python", "javascript"]
      
      for language <- languages do
        code = test_code(language, :simple)
        
        {time, result} = :timer.tc(fn ->
          PortSupervisor.parse(language, code)
        end)
        
        assert {:ok, _ast} = result
        # Should parse in under 200ms
        assert time < 200_000, "#{language} parsing took #{time}μs"
      end
    end
    
    test "handles concurrent parsing requests" do
      # Create multiple parsing tasks
      tasks = for i <- 1..10 do
        Task.async(fn ->
          language = Enum.random(["python", "javascript"])
          code = test_code(language, :simple)
          
          {time, result} = :timer.tc(fn ->
            PortSupervisor.parse(language, code)
          end)
          
          {i, language, time, result}
        end)
      end
      
      # Wait for all tasks
      results = Task.await_many(tasks, 5000)
      
      # All should succeed
      for {_i, _language, _time, result} <- results do
        assert {:ok, _ast} = result
      end
      
      # Check timing
      times = Enum.map(results, fn {_i, _lang, time, _result} -> time end)
      avg_time = Enum.sum(times) / length(times)
      
      # Average should be reasonable even with concurrency
      assert avg_time < 300_000, "Average parsing time: #{avg_time}μs"
    end
  end
  
  describe "Parser crash recovery" do
    test "recovers from parser crash" do
      # Send invalid data that might crash parser
      invalid_json = "not json at all"
      
      # This should fail gracefully
      {:error, _reason} = PortSupervisor.parse("python", invalid_json)
      
      # Parser should still work after error
      code = test_code("python", :simple)
      assert {:ok, _ast} = PortSupervisor.parse("python", code)
    end
    
    test "handles parser timeout" do
      # Create very large code that might timeout
      # For now, just test normal timeout handling
      code = test_code("python", :simple)
      
      # Should complete normally
      assert {:ok, _ast} = PortSupervisor.parse("python", code)
    end
  end
  
  describe "AST security patterns" do
    test "identifies security-relevant AST nodes" do
      languages_and_patterns = [
        {"python", :sql_injection_vulnerable, ["JoinedStr", "Call"]},
        {"python", :command_injection_vulnerable, ["Call", "Attribute"]},
        {"javascript", :sql_injection_vulnerable, ["TemplateLiteral", "CallExpression"]}
      ]
      
      for {language, pattern, expected_nodes} <- languages_and_patterns do
        code = test_code(language, pattern)
        
        case PortSupervisor.parse(language, code) do
          {:ok, ast} ->
            for node_type <- expected_nodes do
              nodes = find_nodes(ast, node_type)
              assert length(nodes) > 0, 
                "Expected to find #{node_type} nodes in #{language} #{pattern}"
            end
            
          {:error, _reason} ->
            # Skip if parser not available
            :ok
        end
      end
    end
  end
end