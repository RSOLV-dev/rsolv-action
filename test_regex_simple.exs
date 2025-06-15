# Test simple regex debug

test_str = ~S|die("Connection failed: " . mysql_error());|
IO.puts("Testing string: #{test_str}")

# Check each part
regex1 = ~r/(die|exit)/
IO.puts("Matches die|exit? #{Regex.match?(regex1, test_str)}")

regex2 = ~r/(die|exit)\s*\(/
IO.puts("Matches die( ? #{Regex.match?(regex2, test_str)}")

regex3 = ~r/(die|exit)\s*\(\s*["']/
IO.puts("Matches die(\" ? #{Regex.match?(regex3, test_str)}")

regex4 = ~r/(die|exit)\s*\(\s*["'][^"']*["']/
IO.puts("Matches die(\"...\" ? #{Regex.match?(regex4, test_str)}")

regex5 = ~r/(die|exit)\s*\(\s*["'][^"']*["']\s*\./
IO.puts("Matches die(\"...\" . ? #{Regex.match?(regex5, test_str)}")

regex6 = ~r/(die|exit)\s*\(\s*["'][^"']*["']\s*\.\s*\w+/
IO.puts("Matches die(\"...\" . word ? #{Regex.match?(regex6, test_str)}")

# Check with "error" in the string
regex7 = ~r/(die|exit)\s*\(\s*["'][^"']*error[^"']*["']\s*\.\s*\w+/
IO.puts("Matches with 'error' requirement? #{Regex.match?(regex7, test_str)}")

IO.puts("\nTesting with error in string:")
test_str2 = ~S|die("Error: " . mysqli_error($conn));|
IO.puts("String: #{test_str2}")
IO.puts("Matches? #{Regex.match?(regex7, test_str2)}")
