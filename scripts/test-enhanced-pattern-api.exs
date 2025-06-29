#!/usr/bin/env elixir

# Test script to debug enhanced pattern API response

# Get a pattern and enhance it
alias RsolvApi.Security.ASTPattern
alias RsolvApi.Security.Patterns.Javascript.SqlInjectionConcat

# Get the base pattern
pattern = SqlInjectionConcat.pattern()
IO.puts("Base pattern ID: #{pattern.id}")
IO.puts("Base pattern keys: #{inspect(Map.keys(pattern))}")

# Enhance it
enhanced = ASTPattern.enhance(pattern)
IO.puts("\nEnhanced pattern type: #{inspect(enhanced.__struct__)}")
IO.puts("Enhanced pattern keys: #{inspect(Map.keys(Map.from_struct(enhanced)))}")
IO.puts("Has ast_rules? #{Map.has_key?(Map.from_struct(enhanced), :ast_rules)}")
IO.puts("Has context_rules? #{Map.has_key?(Map.from_struct(enhanced), :context_rules)}")
IO.puts("Has confidence_rules? #{Map.has_key?(Map.from_struct(enhanced), :confidence_rules)}")

# Test the formatting
# Simulate what happens in the controller
formatted = enhanced
  |> Map.from_struct()
  |> Map.delete(:default_tier)
  |> Map.delete(:tier)

IO.puts("\nFormatted pattern keys before format_ast_enhanced_pattern: #{inspect(Map.keys(formatted))}")

# Now apply the format_ast_enhanced_pattern function
format_ast_enhanced_pattern = fn pattern_map ->
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
end

final_formatted = format_ast_enhanced_pattern.(formatted)
IO.puts("\nFinal formatted pattern keys: #{inspect(Map.keys(final_formatted))}")
IO.puts("Has ast_rules in final? #{Map.has_key?(final_formatted, :ast_rules)}")
IO.puts("Has context_rules in final? #{Map.has_key?(final_formatted, :context_rules)}")
IO.puts("Has confidence_rules in final? #{Map.has_key?(final_formatted, :confidence_rules)}")

# Show what the ast_rules look like
IO.puts("\nAST rules from enhanced pattern:")
IO.inspect(enhanced.ast_rules, pretty: true, limit: :infinity)