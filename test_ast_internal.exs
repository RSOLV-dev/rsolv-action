# Test AST analysis internally
IO.puts("🔍 Testing AST Analysis Internally")
IO.puts("=" <> String.duplicate("=", 60))

# Start the application if not started
Application.ensure_all_started(:rsolv_api)

# Test code
test_code = """
query = "SELECT * FROM users WHERE id = " + user_id
"""

# Test 1: PatternAdapter
IO.puts("\n1. Testing PatternAdapter:")
patterns = RsolvApi.AST.PatternAdapter.load_patterns_for_language("python")
IO.puts("   Loaded #{length(patterns)} patterns")

# Test 2: AST parsing
IO.puts("\n2. Testing AST parsing:")
case RsolvApi.AST.Parser.parse(test_code, "python") do
  {:ok, ast} ->
    IO.puts("   AST parsed successfully")
    IO.puts("   Root type: #{ast["type"]}")
  {:error, reason} ->
    IO.puts("   Error: #{inspect(reason)}")
end

# Test 3: Full analysis
IO.puts("\n3. Testing full AST analysis:")
case RsolvApi.AST.AnalysisService.analyze_files([
  %{
    "path" => "test.py",
    "content" => test_code,
    "language" => "python"
  }
]) do
  {:ok, results} ->
    IO.puts("   Analysis completed")
    IO.puts("   Results: #{inspect(results)}")
  {:error, reason} ->
    IO.puts("   Error: #{inspect(reason)}")
end