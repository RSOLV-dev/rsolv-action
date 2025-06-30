# Simple test to run in IEx
alias RsolvApi.AST.{PatternAdapter, ASTPatternMatcher}

# Load Python patterns
patterns = PatternAdapter.load_patterns_for_language("python")
sql_pattern = Enum.find(patterns, &String.contains?(&1.id, "sql-injection-concat"))

if sql_pattern do
  IO.puts("Pattern found: #{sql_pattern.id}")
  IO.puts("AST pattern:")
  IO.inspect(sql_pattern.ast_pattern, pretty: true)
  
  # Test Python AST
  python_ast = %{
    "type" => "BinOp",
    "op" => %{"type" => "Add"},
    "left" => %{"type" => "Constant", "value" => "SELECT * FROM users WHERE id = "},
    "right" => %{"type" => "Name", "id" => "user_id"}
  }
  
  matches = ASTPatternMatcher.matches_pattern?(python_ast, sql_pattern.ast_pattern)
  IO.puts("\nPattern matches: #{matches}")
  
  # Debug each field
  IO.puts("\nChecking fields:")
  IO.puts("Type match: #{python_ast["type"]} == #{sql_pattern.ast_pattern["type"]}")
  IO.puts("Op present in pattern: #{Map.has_key?(sql_pattern.ast_pattern, "op")}")
  if Map.has_key?(sql_pattern.ast_pattern, "op") do
    IO.puts("Op match: #{inspect(python_ast["op"])} vs #{inspect(sql_pattern.ast_pattern["op"])}")
  end
end