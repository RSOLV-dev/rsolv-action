# Debug pattern loading issue
IO.puts("🔍 Debugging Pattern Loading")
IO.puts("=" <> String.duplicate("=", 60))

# Test 1: Check Application.spec
IO.puts("\n1. Testing Application.spec(:rsolv_api, :modules)")
modules = Application.spec(:rsolv_api, :modules)
IO.puts("   Result: #{inspect(modules)}")
if is_list(modules) do
  IO.puts("   Module count: #{length(modules)}")
  pattern_modules = Enum.filter(modules, fn m -> 
    String.contains?(to_string(m), "Patterns")
  end)
  IO.puts("   Pattern modules: #{length(pattern_modules)}")
end

# Test 2: Check if application is loaded
IO.puts("\n2. Testing Application.loaded_applications()")
loaded = Application.loaded_applications()
rsolv_app = Enum.find(loaded, fn {app, _, _} -> app == :rsolv_api end)
IO.puts("   RSOLV API loaded? #{not is_nil(rsolv_app)}")

# Test 3: Try to ensure application is started
IO.puts("\n3. Ensuring application is started")
case Application.ensure_all_started(:rsolv_api) do
  {:ok, apps} ->
    IO.puts("   Started apps: #{inspect(apps)}")
  {:error, reason} ->
    IO.puts("   Error: #{inspect(reason)}")
end

# Test 4: Now check PatternRegistry again
IO.puts("\n4. Testing PatternRegistry after app start")
try do
  patterns = RsolvApi.Security.PatternRegistry.get_patterns_for_language("python")
  IO.puts("   Patterns loaded: #{length(patterns)}")
  
  if length(patterns) > 0 do
    first = hd(patterns)
    IO.puts("   First pattern ID: #{first.id}")
  end
rescue
  e ->
    IO.puts("   Error: #{Exception.message(e)}")
end

# Test 5: Check PatternServer
IO.puts("\n5. Checking PatternServer status")
case Process.whereis(RsolvApi.Security.PatternServer) do
  nil -> IO.puts("   PatternServer NOT running")
  pid -> 
    IO.puts("   PatternServer running at #{inspect(pid)}")
    # Try to get patterns from server
    try do
      patterns = GenServer.call(pid, {:get_patterns, "python"})
      IO.puts("   Server returned #{length(patterns)} patterns")
    rescue
      e -> IO.puts("   Server call error: #{Exception.message(e)}")
    end
end

# Test 6: Direct module check
IO.puts("\n6. Checking pattern modules directly")
sql_module = RsolvApi.Security.Patterns.Python.SqlInjectionConcat
IO.puts("   Module exists? #{Code.ensure_loaded?(sql_module)}")
if Code.ensure_loaded?(sql_module) do
  pattern = sql_module.pattern()
  IO.puts("   Pattern ID: #{pattern.id}")
  IO.puts("   Pattern struct: #{inspect(pattern.__struct__)}")
end