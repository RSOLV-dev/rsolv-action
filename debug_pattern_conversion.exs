#!/usr/bin/env elixir

# Debug script to understand pattern conversion
IO.puts("\n=== Testing Pattern Conversion ===\n")

alias RsolvApi.Security.PatternRegistry
alias RsolvApi.AST.PatternAdapter

# 1. Load Python patterns
IO.puts("1. Loading Python SQL injection pattern...")
python_patterns = PatternRegistry.get_patterns_for_language("python")
sql_pattern = Enum.find(python_patterns, &String.contains?(&1.id, "sql-injection-concat"))

if sql_pattern do
  IO.puts("   Found: #{sql_pattern.id}")
  
  # 2. Check what ast_enhancement returns
  pattern_module = RsolvApi.Security.Patterns.Python.SqlInjectionConcat
  enhancement = pattern_module.ast_enhancement()
  
  IO.puts("\n2. AST Enhancement from pattern module:")
  IO.puts("   node_type: #{inspect(enhancement.ast_rules.node_type)}")
  IO.puts("   op: #{inspect(enhancement.ast_rules.op)}")
  
  # 3. Check what PatternAdapter does
  IO.puts("\n3. Pattern Adapter conversion:")
  adapted = PatternAdapter.load_patterns_for_language("python")
  sql_adapted = Enum.find(adapted, &String.contains?(&1.id, "sql-injection-concat"))
  
  if sql_adapted do
    IO.puts("   Adapted pattern found")
    IO.puts("   AST pattern structure:")
    IO.inspect(sql_adapted.ast_pattern, pretty: true, limit: :infinity)
  else
    IO.puts("   ❌ Pattern not found after adaptation!")
  end
end

# 4. Test pattern matching with Python AST
IO.puts("\n4. Testing pattern match with Python AST...")
python_ast = %{
  "type" => "BinOp",
  "op" => %{"type" => "Add"},
  "left" => %{
    "type" => "Constant",
    "value" => "SELECT * FROM users WHERE id = "
  },
  "right" => %{
    "type" => "Name",
    "id" => "user_id"
  }
}

alias RsolvApi.AST.ASTPatternMatcher

if sql_adapted do
  # Test direct pattern matching
  matches = ASTPatternMatcher.matches_pattern?(python_ast, sql_adapted.ast_pattern)
  IO.puts("   Direct pattern match: #{matches}")
  
  if !matches do
    IO.puts("\n   Debugging mismatch:")
    IO.puts("   Expected node type: #{inspect(sql_adapted.ast_pattern["type"])}")
    IO.puts("   Actual node type: #{inspect(python_ast["type"])}")
    IO.puts("   Expected operator: #{inspect(sql_adapted.ast_pattern["operator"])}")
    IO.puts("   Actual operator: #{inspect(python_ast["op"])}")
  end
end

IO.puts("\n=== DONE ===")