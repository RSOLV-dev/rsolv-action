#!/usr/bin/env elixir

# Test the full AST detection flow
IO.puts("\n=== Testing Full AST Detection Flow ===\n")

alias RsolvApi.AST.{AnalysisService, SessionManager, ParserRegistry, PatternAdapter}
alias RsolvApi.Security.PatternRegistry

# Ensure services are running
unless GenServer.whereis(SessionManager), do: {:ok, _} = SessionManager.start_link()
unless GenServer.whereis(ParserRegistry), do: {:ok, _} = ParserRegistry.start_link()
unless GenServer.whereis(AnalysisService), do: {:ok, _} = AnalysisService.start_link()

# Test both JavaScript and Python
test_cases = [
  %{
    language: "javascript",
    code: """
    function getUserData(userId) {
      const query = "SELECT * FROM users WHERE id = " + userId;
      return db.query(query);
    }
    """,
    expected_pattern: "js-sql-injection-concat"
  },
  %{
    language: "python", 
    code: """
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)
    """,
    expected_pattern: "python-sql-injection-concat"
  }
]

Enum.each(test_cases, fn test ->
  IO.puts("\n=== Testing #{String.capitalize(test.language)} ===")
  
  # 1. Test pattern loading
  IO.puts("\n1. Pattern Loading:")
  patterns = PatternRegistry.get_patterns_for_language(test.language)
  IO.puts("   Total patterns: #{length(patterns)}")
  
  sql_pattern = Enum.find(patterns, &(&1.id == test.expected_pattern))
  IO.puts("   SQL pattern found: #{sql_pattern != nil}")
  
  # 2. Test pattern adaptation
  IO.puts("\n2. Pattern Adaptation:")
  adapted_patterns = PatternAdapter.load_patterns_for_language(test.language)
  IO.puts("   Adapted patterns: #{length(adapted_patterns)}")
  
  sql_adapted = Enum.find(adapted_patterns, &(&1.id == test.expected_pattern))
  if sql_adapted do
    IO.puts("   SQL pattern adapted: ✓")
    IO.puts("   AST pattern type: #{inspect(sql_adapted.ast_pattern["type"])}")
    
    # Show operator handling for debugging
    if test.language == "python" do
      IO.puts("   AST pattern op: #{inspect(sql_adapted.ast_pattern["op"])}")
    else
      IO.puts("   AST pattern operator: #{inspect(sql_adapted.ast_pattern["operator"])}")
    end
  else
    IO.puts("   SQL pattern adapted: ✗")
  end
  
  # 3. Test AST parsing
  IO.puts("\n3. AST Parsing:")
  {:ok, session} = SessionManager.create_session("test")
  
  case ParserRegistry.parse_code(session.id, "test", test.language, test.code) do
    {:ok, parse_result} ->
      IO.puts("   Parse successful: ✓")
      IO.puts("   AST nodes: #{count_nodes(parse_result.ast)}")
      
      # Find the concatenation node
      concat_node = find_concat_node(parse_result.ast, test.language)
      if concat_node do
        IO.puts("   Concat node found: ✓")
        IO.puts("   Node type: #{inspect(concat_node["type"])}")
        if test.language == "python" do
          IO.puts("   Op type: #{inspect(get_in(concat_node, ["op", "type"]))}")
        else
          IO.puts("   Operator: #{inspect(concat_node["operator"])}")
        end
      else
        IO.puts("   Concat node found: ✗")
      end
      
      # 4. Test full analysis
      IO.puts("\n4. Full Analysis:")
      file = %{
        path: "test.#{if test.language == "python", do: "py", else: "js"}",
        content: test.code,
        language: test.language,
        metadata: %{}
      }
      
      options = %{
        "patternFormat" => "enhanced",
        "includeSecurityPatterns" => true
      }
      
      case AnalysisService.analyze_file(file, options) do
        {:ok, findings} ->
          IO.puts("   Analysis complete: ✓")
          IO.puts("   Findings: #{length(findings)}")
          
          if length(findings) > 0 do
            Enum.each(findings, fn finding ->
              IO.puts("   - #{finding.patternId}: #{finding.patternName} (#{finding.confidence} confidence)")
            end)
          else
            IO.puts("   ⚠️  No vulnerabilities detected!")
            
            # Debug: Check if patterns are being matched
            if sql_adapted && concat_node do
              IO.puts("\n   Debugging pattern match:")
              alias RsolvApi.AST.ASTPatternMatcher
              matches = ASTPatternMatcher.matches_pattern?(concat_node, sql_adapted.ast_pattern)
              IO.puts("   Direct pattern match: #{matches}")
              
              if !matches do
                IO.puts("   Pattern structure:")
                IO.inspect(sql_adapted.ast_pattern, pretty: true, limit: 3)
                IO.puts("   Node structure:")
                IO.inspect(concat_node, pretty: true, limit: 3)
              end
            end
          end
          
        {:error, reason} ->
          IO.puts("   Analysis failed: #{inspect(reason)}")
      end
      
    {:error, reason} ->
      IO.puts("   Parse failed: #{inspect(reason)}")
  end
end)

# Helper functions
defp count_nodes(ast) when is_map(ast) do
  1 + Enum.reduce(ast, 0, fn
    {_k, v}, acc when is_map(v) -> acc + count_nodes(v)
    {_k, v}, acc when is_list(v) -> acc + Enum.reduce(v, 0, &(&2 + count_nodes(&1)))
    _, acc -> acc
  end)
end
defp count_nodes(ast) when is_list(ast), do: Enum.reduce(ast, 0, &(&2 + count_nodes(&1)))
defp count_nodes(_), do: 1

defp find_concat_node(ast, "javascript") do
  find_node_by_type(ast, "BinaryExpression", fn node ->
    node["operator"] == "+"
  end)
end

defp find_concat_node(ast, "python") do
  find_node_by_type(ast, "BinOp", fn node ->
    get_in(node, ["op", "type"]) == "Add"
  end)
end

defp find_node_by_type(ast, type, filter_fn) when is_map(ast) do
  if ast["type"] == type && filter_fn.(ast) do
    ast
  else
    Enum.reduce_while(ast, nil, fn
      {_k, v}, _acc when is_map(v) ->
        case find_node_by_type(v, type, filter_fn) do
          nil -> {:cont, nil}
          node -> {:halt, node}
        end
      {_k, v}, _acc when is_list(v) ->
        case Enum.find(v, &find_node_by_type(&1, type, filter_fn)) do
          nil -> {:cont, nil}
          node -> {:halt, node}
        end
      _, acc -> {:cont, acc}
    end)
  end
end
defp find_node_by_type(ast, type, filter_fn) when is_list(ast) do
  Enum.find(ast, &find_node_by_type(&1, type, filter_fn))
end
defp find_node_by_type(_, _, _), do: nil

IO.puts("\n=== DONE ===")