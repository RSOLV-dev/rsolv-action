#!/usr/bin/env elixir

# Test script to debug and fix enhanced format issue

Mix.start()
Mix.shell(Mix.Shell.Process)

# Load the application but don't start it
Application.load(:rsolv_api)

# Import modules
alias RsolvApi.Security.{Pattern, ASTPattern, DemoPatterns}
alias RsolvApi.Security.Patterns.JSONSerializer

IO.puts("Testing Enhanced Format Fix...\n")

# Get a demo pattern
demo_patterns = DemoPatterns.get_demo_patterns("javascript")
pattern = List.first(demo_patterns)

IO.puts("1. Original pattern:")
IO.inspect(pattern, limit: 3)

IO.puts("\n2. Pattern.to_api_format (standard):")
standard_format = Pattern.to_api_format(pattern)
IO.inspect(standard_format, limit: 3)

IO.puts("\n3. Testing ASTPattern.enhance:")
try do
  enhanced = ASTPattern.enhance(pattern)
  IO.puts("✅ Enhancement successful!")
  IO.puts("Type: #{inspect(enhanced.__struct__)}")
  IO.puts("Has regex field: #{Map.has_key?(enhanced, :regex)}")
  IO.puts("Regex value: #{inspect(enhanced.regex)}")
rescue
  e ->
  IO.puts("❌ Enhancement failed: #{inspect(e)}")
end

IO.puts("\n4. Testing JSONSerializer with enhanced pattern:")
# Simulate what the controller does
formatted = Pattern.to_api_format(pattern)
|> Map.delete(:tier)

# Try to enhance
enhanced_pattern = ASTPattern.enhance(pattern)

# Add enhanced fields
formatted_with_enhancement = formatted
|> Map.put(:ast_rules, enhanced_pattern.ast_rules)
|> Map.put(:context_rules, enhanced_pattern.context_rules)
|> Map.put(:confidence_rules, enhanced_pattern.confidence_rules)
|> Map.put(:min_confidence, enhanced_pattern.min_confidence)

IO.puts("\nFormatted with enhancement:")
IO.inspect(Map.keys(formatted_with_enhancement))

# Now try to serialize
IO.puts("\n5. Testing JSON serialization:")
try do
  # First prepare the data
  prepared = JSONSerializer.prepare_for_json(formatted_with_enhancement)
  IO.puts("✅ prepare_for_json successful")
  
  # Then encode
  json = JSON.encode!(prepared)
  IO.puts("✅ JSON.encode! successful")
  IO.puts("JSON length: #{String.length(json)} bytes")
rescue
  e ->
    IO.puts("❌ Serialization failed: #{inspect(e)}")
    IO.puts(Exception.format_stacktrace())
end

# The issue might be that we're losing the original regex when using to_api_format
# Let's check what happens if we keep the original regex
IO.puts("\n6. Testing with original regex preserved:")
formatted_with_regex = formatted
|> Map.put(:regex, pattern.regex)  # Add back the original regex
|> Map.put(:ast_rules, enhanced_pattern.ast_rules)
|> Map.put(:context_rules, enhanced_pattern.context_rules)
|> Map.put(:confidence_rules, enhanced_pattern.confidence_rules)
|> Map.put(:min_confidence, enhanced_pattern.min_confidence)

try do
  prepared = JSONSerializer.prepare_for_json(formatted_with_regex)
  _json = JSON.encode!(prepared)
  IO.puts("✅ With regex preserved: JSON encoding successful!")
rescue
  e ->
    IO.puts("❌ Still failed: #{inspect(e)}")
end