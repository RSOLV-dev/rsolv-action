# Test script for ValidationCache.KeyGenerator
alias Rsolv.ValidationCache.KeyGenerator

# This is what the controller is passing based on the error log
test_locations = [%{line: 7, file_path: "routes/users.js"}]

try do
  result = KeyGenerator.generate_key(
    "test-forge-1",
    "unknown/repo",
    test_locations,
    "sql_injection"
  )
  IO.puts("✅ Success: #{result}")
rescue
  e in FunctionClauseError ->
    IO.puts("❌ Function clause error!")
    IO.inspect(e, label: "Error")

    # Test with correct structure
    IO.puts("\nTrying with correct map structure...")
    correct_locations = [%{file_path: "routes/users.js", line: 7}]
    result = KeyGenerator.generate_key(
      "test-forge-1",
      "unknown/repo",
      correct_locations,
      "sql_injection"
    )
    IO.puts("✅ With reordered keys: #{result}")
end