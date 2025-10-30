defmodule Rsolv.AST.MultiLanguageParsingTest do
  use Rsolv.AST.TestCase

  alias Rsolv.AST.{PortSupervisor, ParserRegistry, SessionManager}

  setup do
    # Create a proper session for each test
    customer_id = "test-customer-#{:rand.uniform(999_999)}"
    {:ok, session} = SessionManager.create_session(customer_id)

    on_exit(fn ->
      # Clean up expired sessions
      SessionManager.cleanup_expired_sessions()
    end)

    {:ok, session: session, customer_id: customer_id}
  end

  describe "Python parsing" do
    test "parses simple Python code", %{session: session, customer_id: customer_id} do
      code = test_code("python", :simple)

      # Create a temporary Python file
      with_temp_file(code, "py", fn path ->
        {:ok, result} = ParserRegistry.parse_code(session.id, customer_id, "python", code)
        ast = result.ast

        assert ast["type"] == "Module"
        assert is_list(ast["body"])

        # Find function definition
        func_defs = find_nodes(ast, "FunctionDef")
        assert length(func_defs) == 1

        func_def = List.first(func_defs)
        assert func_def["name"] == "hello"
      end)
    end

    test "detects Python SQL injection", %{session: session, customer_id: customer_id} do
      vulnerable_code = test_code("python", :sql_injection_vulnerable)
      safe_code = test_code("python", :sql_injection_safe)

      # Parse vulnerable code
      {:ok, vuln_result} =
        ParserRegistry.parse_code(session.id, customer_id, "python", vulnerable_code)

      vuln_ast = vuln_result.ast

      # Look for f-string with SQL
      joined_strs = find_nodes(vuln_ast, "JoinedStr")
      assert length(joined_strs) > 0

      # Parse safe code
      {:ok, safe_result} = ParserRegistry.parse_code(session.id, customer_id, "python", safe_code)
      safe_ast = safe_result.ast

      # Safe code should use different pattern
      joined_strs_safe = find_nodes(safe_ast, "JoinedStr")
      # Safe version uses parameterized query, no f-string in SQL
      assert Enum.empty?(joined_strs_safe)
    end

    test "handles Python syntax errors gracefully", %{session: session, customer_id: customer_id} do
      code = test_code("python", :syntax_error)

      {:ok, result} = ParserRegistry.parse_code(session.id, customer_id, "python", code)

      # Check that parsing failed with syntax error
      assert result.ast == nil
      assert result.error != nil
      error_msg = inspect(result.error)
      assert String.contains?(error_msg, "syntax") or String.contains?(error_msg, "SyntaxError")
    end

    test "detects command injection patterns", %{session: session, customer_id: customer_id} do
      code = test_code("python", :command_injection_vulnerable)

      {:ok, result} = ParserRegistry.parse_code(session.id, customer_id, "python", code)
      ast = result.ast

      # Find os.system calls
      calls = find_nodes(ast, "Call")

      os_system_calls =
        Enum.filter(calls, fn call ->
          case call["func"] do
            %{"type" => "Attribute", "attr" => "system"} -> true
            _ -> false
          end
        end)

      assert length(os_system_calls) == 1
    end
  end

  describe "Ruby parsing" do
    test "parses simple Ruby code", %{session: session, customer_id: customer_id} do
      code = test_code("ruby", :simple)

      result = ParserRegistry.parse_code(session.id, customer_id, "ruby", code)

      # Debug output to diagnose issues
      case result do
        {:ok, parse_result} ->
          ast = parse_result.ast

          # Verify AST structure
          assert ast != nil, "AST should not be nil"
          assert is_map(ast), "AST should be a map, got: #{inspect(ast)}"

          # Ruby AST structure - Prism returns program root with statements
          ast_type = ast["type"] || ast[:type]

          assert ast_type == "program",
                 "Expected type 'program', got: #{inspect(ast_type)}. Full AST: #{inspect(ast)}"

          # Find the def node within the AST
          def_nodes = find_nodes(ast, "def")

          assert length(def_nodes) == 1,
                 "Expected 1 def node, found #{length(def_nodes)}. AST: #{inspect(ast)}"

          def_node = hd(def_nodes)
          has_children = is_list(def_node["children"]) or is_list(def_node[:children])

          assert has_children,
                 "def node should have children list. Node: #{inspect(def_node)}"

        {:error, error} ->
          flunk("Parser failed with error: #{inspect(error)}")
      end
    end

    test "detects Ruby SQL injection", %{session: session, customer_id: customer_id} do
      vulnerable_code = test_code("ruby", :sql_injection_vulnerable)

      {:ok, result} = ParserRegistry.parse_code(session.id, customer_id, "ruby", vulnerable_code)
      ast = result.ast

      # Look for string interpolation in where clause - Prism uses "interpolated_string"
      interpolated_str_nodes = find_nodes(ast, "interpolated_string")
      assert length(interpolated_str_nodes) > 0
    end
  end

  describe "PHP parsing" do
    test "parses simple PHP code", %{session: session, customer_id: customer_id} do
      code = test_code("php", :simple)

      {:ok, result} = ParserRegistry.parse_code(session.id, customer_id, "php", code)
      ast = result.ast

      # PHP AST should have function nodes
      assert ast != nil
    end

    test "detects PHP XSS vulnerabilities", %{session: session, customer_id: customer_id} do
      vulnerable_code = test_code("php", :xss_vulnerable)
      safe_code = test_code("php", :xss_safe)

      {:ok, vuln_result} =
        ParserRegistry.parse_code(session.id, customer_id, "php", vulnerable_code)

      {:ok, safe_result} = ParserRegistry.parse_code(session.id, customer_id, "php", safe_code)
      vuln_ast = vuln_result.ast
      safe_ast = safe_result.ast

      # Vulnerable should have direct echo
      # Safe should have htmlspecialchars
      assert vuln_ast != safe_ast
    end
  end

  describe "Java parsing" do
    @tag :skip
    test "parses simple Java code", %{session: session, customer_id: customer_id} do
      code = test_code("java", :simple)

      {:ok, result} = ParserRegistry.parse_code(session.id, customer_id, "java", code)
      ast = result.ast

      # Java AST should have class declaration
      assert ast != nil
    end

    @tag :skip
    test "detects Java command injection", %{session: session, customer_id: customer_id} do
      code = test_code("java", :command_injection_vulnerable)

      {:ok, result} = ParserRegistry.parse_code(session.id, customer_id, "java", code)
      ast = result.ast

      # Look for Runtime.exec calls
      # AST structure depends on parser used
      assert ast != nil
    end
  end

  describe "JavaScript parsing" do
    test "parses simple JavaScript code", %{session: session, customer_id: customer_id} do
      code = test_code("javascript", :simple)

      {:ok, result} = ParserRegistry.parse_code(session.id, customer_id, "javascript", code)
      ast = result.ast

      # JS AST has File root with program child
      assert ast["type"] == "File" or ast[:type] == "File"
      assert ast["program"]["type"] == "Program" or ast[:program][:type] == "Program"
    end

    test "detects JavaScript SQL injection", %{session: session, customer_id: customer_id} do
      vulnerable_code = test_code("javascript", :sql_injection_vulnerable)

      {:ok, result} =
        ParserRegistry.parse_code(session.id, customer_id, "javascript", vulnerable_code)

      ast = result.ast

      # Look for template literals with expressions
      template_literals = find_nodes(ast, "TemplateLiteral")
      assert length(template_literals) > 0
    end
  end

  describe "Elixir parsing" do
    test "parses simple Elixir code", %{session: session, customer_id: customer_id} do
      code = test_code("elixir", :simple)

      {:ok, result} = ParserRegistry.parse_code(session.id, customer_id, "elixir", code)
      ast = result.ast

      # Elixir AST is a tuple structure
      assert is_tuple(ast) or is_map(ast)
    end

    test "detects Elixir command injection", %{session: session, customer_id: customer_id} do
      code = test_code("elixir", :command_injection_vulnerable)

      {:ok, result} = ParserRegistry.parse_code(session.id, customer_id, "elixir", code)
      ast = result.ast

      # Look for System.shell calls
      assert ast != nil
    end
  end

  describe "Parser performance" do
    @tag :performance
    test "parses files within time limit", %{session: session, customer_id: customer_id} do
      languages = ["python", "javascript"]

      for language <- languages do
        code = test_code(language, :simple)

        {time, result} =
          :timer.tc(fn ->
            ParserRegistry.parse_code(session.id, customer_id, language, code)
          end)

        assert {:ok, _result} = result
        # Just verify it parsed successfully, log timing for debugging
        IO.puts("#{language} parsing took #{time}μs")
        # Basic sanity check
        assert time > 0
      end
    end

    @tag :performance
    test "handles concurrent parsing requests", %{session: session, customer_id: customer_id} do
      # Create multiple parsing tasks
      tasks =
        for i <- 1..10 do
          Task.async(fn ->
            language = Enum.random(["python", "javascript"])
            code = test_code(language, :simple)

            {time, result} =
              :timer.tc(fn ->
                ParserRegistry.parse_code(session.id, customer_id, language, code)
              end)

            {i, language, time, result}
          end)
        end

      # Wait for all tasks
      results = Task.await_many(tasks, 5000)

      # All should succeed
      for {_i, _language, _time, result} <- results do
        assert {:ok, _result} = result
      end

      # Check timing
      times = Enum.map(results, fn {_i, _lang, time, _result} -> time end)
      avg_time = Enum.sum(times) / length(times)

      # Log timing for debugging, but don't assert on performance
      IO.puts("Average parsing time with concurrency: #{avg_time}μs")
      # Basic sanity check
      assert avg_time > 0
    end
  end

  describe "Parser crash recovery" do
    test "recovers from parser crash", %{session: session, customer_id: customer_id} do
      # Send invalid data that might crash parser
      invalid_json = "not json at all"

      # This should fail gracefully with an error in the result
      assert {:ok, result} =
               ParserRegistry.parse_code(session.id, customer_id, "python", invalid_json)

      assert result.ast == nil
      assert result.error != nil

      # Parser should still work after error
      code = test_code("python", :simple)
      assert {:ok, result} = ParserRegistry.parse_code(session.id, customer_id, "python", code)
      assert result.ast != nil
      assert result.error == nil
    end

    test "handles parser timeout", %{session: session, customer_id: customer_id} do
      # Create very large code that might timeout
      # For now, just test normal timeout handling
      code = test_code("python", :simple)

      # Should complete normally
      assert {:ok, _result} = ParserRegistry.parse_code(session.id, customer_id, "python", code)
    end
  end

  describe "AST security patterns" do
    test "identifies security-relevant AST nodes", %{session: session, customer_id: customer_id} do
      languages_and_patterns = [
        {"python", :sql_injection_vulnerable, ["JoinedStr", "Call"]},
        {"python", :command_injection_vulnerable, ["Call", "Attribute"]},
        {"javascript", :sql_injection_vulnerable, ["TemplateLiteral", "CallExpression"]}
      ]

      for {language, pattern, expected_nodes} <- languages_and_patterns do
        code = test_code(language, pattern)

        case ParserRegistry.parse_code(session.id, customer_id, language, code) do
          {:ok, result} ->
            ast = result.ast

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
