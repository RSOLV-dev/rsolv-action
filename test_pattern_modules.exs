# Test pattern modules are available
IO.puts("🔍 Testing Pattern Module Availability")
IO.puts("=" <> String.duplicate("=", 60))

# Check if pattern modules are loaded
modules = :code.all_loaded() 
  |> Enum.map(&elem(&1, 0))
  |> Enum.filter(fn m -> 
    String.contains?(to_string(m), "Patterns.Python")
  end)

IO.puts("\n1. Python pattern modules loaded: #{length(modules)}")
if length(modules) > 0 do
  Enum.each(Enum.take(modules, 5), fn m ->
    IO.puts("   - #{m}")
  end)
end

# Try to load a specific pattern module
sql_module = :"Elixir.RsolvApi.Security.Patterns.Python.SqlInjectionConcat"
IO.puts("\n2. Checking SQL injection pattern module:")
IO.puts("   Module atom: #{inspect(sql_module)}")
IO.puts("   Module loaded? #{Code.ensure_loaded?(sql_module)}")

if Code.ensure_loaded?(sql_module) do
  IO.puts("   Has pattern/0? #{function_exported?(sql_module, :pattern, 0)}")
  
  if function_exported?(sql_module, :pattern, 0) do
    pattern = apply(sql_module, :pattern, [])
    IO.puts("   Pattern ID: #{pattern.id}")
    IO.puts("   Pattern type: #{pattern.type}")
  end
end

# Check all pattern modules via Application
IO.puts("\n3. Checking Application.spec(:rsolv_api, :modules):")
app_modules = Application.spec(:rsolv_api, :modules)
if app_modules do
  pattern_modules = Enum.filter(app_modules, fn m ->
    String.contains?(to_string(m), "Patterns")
  end)
  IO.puts("   Total modules: #{length(app_modules)}")
  IO.puts("   Pattern modules: #{length(pattern_modules)}")
else
  IO.puts("   Application spec returned nil")
end

# Check code paths
IO.puts("\n4. Code paths containing 'rsolv_api':")
:code.get_path()
|> Enum.filter(fn path -> 
  String.contains?(to_string(path), "rsolv_api")
end)
|> Enum.each(fn path ->
  IO.puts("   - #{path}")
end)