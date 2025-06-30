# Test code path and pattern loading
IO.puts("Current code paths:")
:code.get_path() |> Enum.each(&IO.puts("  #{&1}"))

# Add the path if not already there
ebin_path = '/app/_build/dev/lib/rsolv_api/ebin'
if not Enum.member?(:code.get_path(), ebin_path) do
  IO.puts("\nAdding #{ebin_path} to code path...")
  :code.add_path(ebin_path)
end

# Now test loading
module_name = RsolvApi.Security.Patterns.Python.SqlInjectionConcat
IO.puts("\nTesting module: #{inspect(module_name)}")

case Code.ensure_loaded(module_name) do
  {:module, mod} ->
    IO.puts("✅ Successfully loaded: #{inspect(mod)}")
  {:error, reason} ->
    IO.puts("❌ Failed to load: #{inspect(reason)}")
end

# Test if it has the pattern function
if Code.ensure_loaded?(module_name) do
  IO.puts("\nChecking pattern function...")
  if function_exported?(module_name, :pattern, 0) do
    pattern = apply(module_name, :pattern, [])
    IO.puts("✅ Pattern function exists!")
    IO.puts("Pattern ID: #{pattern.id}")
    IO.puts("Has AST pattern? #{not is_nil(pattern.ast_pattern)}")
  else
    IO.puts("❌ Pattern function not found")
  end
end