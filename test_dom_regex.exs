regex = ~r/
  ^(?!.*\/\/).*(?:
    insertAdjacentHTML\s*\(|
    \$\s*\([^)]*\)\s*\.(?:append|prepend|after|before|html)\s*\(|
    jQuery\s*\([^)]*\)\s*\.(?:append|prepend|after|before|html)\s*\(|
    \.outerHTML\s*=
  )
/imx

test_cases = [
  "$target.prepend(query.message)",
  "$(element).append(userInput)",
  "$('#content').prepend(req.body.content)",
  "element.insertAdjacentHTML('beforeend', SAFE_TEMPLATE)"
]

IO.puts("Testing regex pattern:\n")

for test <- test_cases do
  result = Regex.match?(regex, test)
  IO.puts("#{test} => #{result}")
end

# Test without the negative lookahead
simple_regex = ~r/
  (?:
    insertAdjacentHTML\s*\(|
    \$\s*\([^)]*\)\s*\.(?:append|prepend|after|before|html)\s*\(|
    jQuery\s*\([^)]*\)\s*\.(?:append|prepend|after|before|html)\s*\(|
    \.outerHTML\s*=
  )
/imx

IO.puts("\nTesting simplified regex without negative lookahead:\n")

for test <- test_cases do
  result = Regex.match?(simple_regex, test)
  IO.puts("#{test} => #{result}")
end

# Let's also check what's wrong with $target
IO.puts("\nChecking $target issue:")
IO.inspect(String.match?("$target.prepend(query.message)", ~r/\$\s*\([^)]*\)/))
IO.inspect(String.match?("$(element).append(userInput)", ~r/\$\s*\([^)]*\)/))
IO.inspect(String.match?("$target.prepend(query.message)", ~r/\$[a-zA-Z_]\w*\s*\.(?:append|prepend|after|before|html)\s*\(/))