# Test various regex patterns for error_display

test_strings = [
  ~S|die("Database error: " . mysqli_error($conn));|,
  ~S|die("Error: " . pg_last_error());|,
  ~S|die("Error: " . oci_error());|,
  ~S|die("Error: " . sqlsrv_errors());|
]

# Current regex from implementation
current_regex = ~r/(die|exit)\s*\(\s*["'][^"']*error[^"']*["']\s*\.\s*(\w+_(error|errno)|pg_last_error|oci_error|sqlsrv_errors)/

IO.puts("Testing current regex:")
for str <- test_strings do
  match = Regex.match?(current_regex, str)
  IO.puts("#{str} => #{match}")
end

# New regex that should match all patterns
new_regex = ~r/(die|exit)\s*\(\s*["'][^"']*error[^"']*["']\s*\.\s*(\w+_(error|errno)|pg_last_error|oci_error|sqlsrv_errors)\s*\(/

IO.puts("\nTesting new regex with parenthesis:")
for str <- test_strings do
  match = Regex.match?(new_regex, str)
  IO.puts("#{str} => #{match}")
end

# Simpler regex approach
simple_regex = ~r/(die|exit)\s*\(\s*["'][^"']*error[^"']*["']\s*\.\s*\w+/

IO.puts("\nTesting simple regex:")
for str <- test_strings do
  match = Regex.match?(simple_regex, str)
  IO.puts("#{str} => #{match}")
end

# Check if it's matching the functions correctly
IO.puts("\nChecking function matches:")
for str <- test_strings do
  case Regex.run(simple_regex, str) do
    nil -> IO.puts("#{str} => NO MATCH")
    matches -> IO.puts("#{str} => #{inspect(matches)}")
  end
end
