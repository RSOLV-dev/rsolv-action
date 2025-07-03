#!/usr/bin/env elixir

# Test enhanced API format directly

alias Rsolv.Security.ASTPattern
alias RsolvWeb.Api.V1.PatternController
alias RSOLVApi.Security.Patterns.JSONSerializer

# Simulate what happens in the controller for enhanced format
language = "javascript"
format = :enhanced

# Get enhanced patterns
patterns = ASTPattern.get_all_patterns_for_language(language, format)

IO.puts("Got #{length(patterns)} patterns")

# Get first pattern
pattern = List.first(patterns)
IO.puts("\nFirst pattern type: #{inspect(pattern.__struct__)}")
IO.puts("Pattern ID: #{pattern.id}")

# Check if it has AST fields
pattern_map = Map.from_struct(pattern)
IO.puts("\nHas ast_rules? #{Map.has_key?(pattern_map, :ast_rules)}")
IO.puts("Has context_rules? #{Map.has_key?(pattern_map, :context_rules)}")
IO.puts("Has confidence_rules? #{Map.has_key?(pattern_map, :confidence_rules)}")

# Format it like the controller does
formatted = case pattern do
  %ASTPattern{} = p ->
    p
    |> Map.from_struct()
    |> Map.delete(:default_tier)
    |> Map.delete(:tier)
    |> (fn pattern_map ->
      pattern_map
      |> Map.put(:regex_patterns, pattern_map[:regex])
      |> Map.delete(:regex)
      |> Map.put(:type, to_string(pattern_map[:type] || ""))
      |> Map.put(:severity, to_string(pattern_map[:severity] || ""))
      |> Map.update(:test_cases, %{}, fn test_cases ->
        case test_cases do
          %{vulnerable: v, safe: s} -> %{vulnerable: v, safe: s}
          _ -> %{vulnerable: [], safe: []}
        end
      end)
      |> Map.put(:examples, %{
        vulnerable: get_in(pattern_map, [:test_cases, :vulnerable]) |> List.first() || "",
        safe: get_in(pattern_map, [:test_cases, :safe]) |> List.first() || ""
      })
    end).()
    
  _ ->
    IO.puts("Not an ASTPattern!")
    %{}
end

IO.puts("\nFormatted pattern keys:")
IO.inspect(Map.keys(formatted) |> Enum.sort())

# Check for AST fields in formatted output
IO.puts("\nFormatted has ast_rules? #{Map.has_key?(formatted, :ast_rules)}")
IO.puts("Formatted has context_rules? #{Map.has_key?(formatted, :context_rules)}")
IO.puts("Formatted has confidence_rules? #{Map.has_key?(formatted, :confidence_rules)}")

# Test JSON serialization
response_data = %{
  patterns: [formatted],
  metadata: %{
    language: language,
    format: to_string(format),
    count: 1,
    enhanced: true,
    access_level: "full"
  }
}

try do
  json_data = JSONSerializer.encode!(response_data)
  IO.puts("\nJSON serialization successful!")
  IO.puts("JSON length: #{String.length(json_data)} bytes")
  
  # Parse it back to check structure
  parsed = JSON.decode!(json_data)
  first_pattern = List.first(parsed["patterns"])
  IO.puts("\nParsed pattern has ast_rules? #{Map.has_key?(first_pattern, "ast_rules")}")
  IO.puts("Parsed pattern has context_rules? #{Map.has_key?(first_pattern, "context_rules")}")
  IO.puts("Parsed pattern has confidence_rules? #{Map.has_key?(first_pattern, "confidence_rules")}")
rescue
  e ->
    IO.puts("\nError during JSON serialization:")
    IO.inspect(e)
    IO.puts("\nStacktrace:")
    IO.puts(Exception.format_stacktrace())
end