test_str = ~S|die("Error: " . mysqli_error($conn));|
IO.puts("Testing: #{test_str}")

# Current regex that should work
regex = ~r/(die|exit)\s*\(\s*["'][^"']*error[^"']*["']\s*\.\s*\w+/

# Run the regex and see what it captures
case Regex.run(regex, test_str) do
  nil -> IO.puts("No match")
  matches -> IO.puts("Matches: #{inspect(matches)}")
end

# Check the exact issue
IO.puts("\nChecking character by character:")
IO.puts("String chars: #{inspect(String.graphemes(test_str))}")

# Try without requiring "error" in the string
regex2 = ~r/(die|exit)\s*\(\s*["'][^"']*["']\s*\.\s*mysqli_error/
IO.puts("\nDirect function match: #{Regex.match?(regex2, test_str)}")

# The issue might be the parentheses after mysqli_error
# Let's see what happens if we stop at the function name
IO.puts("\nExtracting matches:")
case Regex.run(~r/(die|exit)\s*\(\s*["']([^"']*["']\s*\.\s*\w+)/, test_str) do
  nil -> IO.puts("No match")
  [full, func, content] -> 
    IO.puts("Full: #{full}")
    IO.puts("Function: #{func}")
    IO.puts("Content: #{content}")
end
