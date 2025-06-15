# Test specific failing cases
regex = ~r/(die|exit)\s*\(\s*["'][^"']*error[^"']*["']\s*\.\s*[\w_]+\s*\(/

failing_cases = [
  ~S|die("Connection failed: " . mysql_error());|,
  ~S|exit("Query failed: " . pg_last_error());|,
  ~S|die( "Error: " . mysqli_error($conn) );|
]

IO.puts("Testing specific failing cases:")
for test <- failing_cases do
  match = Regex.match?(regex, test)
  IO.puts("#{test}")
  IO.puts("  => #{match}")
  IO.puts("  Has 'error' in string? #{String.contains?(test, ~s|"Error|) or String.contains?(test, ~s|'Error|)}")
  IO.puts("")
end

# Test with case-insensitive
regex_ci = ~r/(die|exit)\s*\(\s*["'][^"']*["']\s*\.\s*[\w_]+\s*\(/i

IO.puts("\nTesting without requiring 'error' in the message:")
for test <- failing_cases do
  match = Regex.match?(regex_ci, test)
  IO.puts("#{test} => #{match}")
end
