# Test PatternRegistry directly
IO.puts("🔍 Testing PatternRegistry")
IO.puts("=" <> String.duplicate("=", 60))

try do
  # Get patterns from registry
  patterns = RsolvApi.Security.PatternRegistry.get_patterns_for_language("python")
  IO.puts("PatternRegistry returned #{length(patterns)} patterns")
  
  if length(patterns) > 0 do
    first = hd(patterns)
    IO.puts("\nFirst pattern:")
    IO.puts("  ID: #{first.id}")
    IO.puts("  Type: #{first.type}")
    IO.puts("  Struct: #{inspect(first.__struct__)}")
  end
  
  # Check if PatternServer is running
  IO.puts("\n--- Checking PatternServer ---")
  case Process.whereis(RsolvApi.Security.PatternServer) do
    nil -> IO.puts("PatternServer is NOT running")
    pid -> IO.puts("PatternServer is running at #{inspect(pid)}")
  end
  
  # Try GenServer call directly
  IO.puts("\n--- Direct GenServer call ---")
  case GenServer.call(RsolvApi.Security.PatternServer, {:get_patterns, "python"}, 5000) do
    patterns when is_list(patterns) ->
      IO.puts("Direct call returned #{length(patterns)} patterns")
    error ->
      IO.puts("Direct call error: #{inspect(error)}")
  end
rescue
  e ->
    IO.puts("Error: #{Exception.message(e)}")
    IO.inspect(__STACKTRACE__, pretty: true)
end