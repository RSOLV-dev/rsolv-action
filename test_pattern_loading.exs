# Test pattern loading without starting the application
require Logger

Logger.configure(level: :debug)

# Test if module is available
module_name = RsolvApi.Security.Patterns.Python.SqlInjectionConcat
IO.puts("Testing module: #{inspect(module_name)}")
IO.puts("Module loaded? #{Code.ensure_loaded?(module_name)}")

# Try to load it explicitly
case Code.ensure_loaded(module_name) do
  {:module, mod} ->
    IO.puts("Successfully loaded: #{inspect(mod)}")
  {:error, reason} ->
    IO.puts("Failed to load: #{inspect(reason)}")
end

# Check if the beam file exists
beam_path = "/app/_build/dev/lib/rsolv_api/ebin/Elixir.RsolvApi.Security.Patterns.Python.SqlInjectionConcat.beam"
IO.puts("Beam file exists? #{File.exists?(beam_path)}")

# Try to load patterns through PatternAdapter
try do
  patterns = RsolvApi.AST.PatternAdapter.load_patterns_for_language("python")
  IO.puts("PatternAdapter loaded #{length(patterns)} patterns")
  
  sql_pattern = Enum.find(patterns, &(String.contains?(&1.id || "", "sql")))
  if sql_pattern do
    IO.puts("SQL pattern: #{sql_pattern.id}")
    IO.puts("Has ast_pattern? #{not is_nil(Map.get(sql_pattern, :ast_pattern))}")
  end
rescue
  e ->
    IO.puts("Error loading patterns: #{inspect(e)}")
end