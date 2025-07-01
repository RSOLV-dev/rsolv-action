# Test pattern loading without starting the full app
IO.puts("🔍 Testing Pattern Loading Fix")
IO.puts("=" <> String.duplicate("=", 60))

# Load necessary modules
Code.require_file("lib/rsolv_api/security/pattern.ex")
Code.require_file("lib/rsolv_api/security/ast_pattern.ex")
Code.require_file("lib/rsolv_api/security/pattern_registry.ex")
Code.require_file("lib/rsolv_api/ast/pattern_adapter.ex")

# Direct test of PatternRegistry
IO.puts("\n1. Testing PatternRegistry directly:")
patterns = RsolvApi.Security.PatternRegistry.get_patterns_for_language("python")
IO.puts("   Found #{length(patterns)} patterns")

if length(patterns) > 0 do
  sql_pattern = Enum.find(patterns, fn p -> String.contains?(p.id || "", "sql") end)
  if sql_pattern do
    IO.puts("   SQL pattern found: #{sql_pattern.id}")
    IO.puts("   Pattern struct: #{inspect(sql_pattern.__struct__)}")
  end
end

# Test PatternAdapter
IO.puts("\n2. Testing PatternAdapter:")
enhanced_patterns = RsolvApi.AST.PatternAdapter.load_patterns_for_language("python")
IO.puts("   Enhanced patterns: #{length(enhanced_patterns)}")

if length(enhanced_patterns) > 0 do
  first = hd(enhanced_patterns)
  IO.puts("\n3. First enhanced pattern:")
  IO.puts("   ID: #{first[:id]}")
  IO.puts("   Has ast_pattern? #{not is_nil(first[:ast_pattern])}")
  
  if first[:ast_pattern] do
    IO.puts("   AST pattern type: #{inspect(first[:ast_pattern]["type"])}")
  end
end

# Test SQL injection pattern specifically
sql_patterns = Enum.filter(enhanced_patterns, fn p -> 
  String.contains?(p[:id] || "", "sql")
end)

IO.puts("\n4. SQL injection patterns found: #{length(sql_patterns)}")
if length(sql_patterns) > 0 do
  sql_pattern = hd(sql_patterns)
  IO.puts("   Pattern: #{sql_pattern[:id]}")
  IO.puts("   AST pattern: #{inspect(sql_pattern[:ast_pattern])}")
end