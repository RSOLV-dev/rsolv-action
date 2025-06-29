#!/usr/bin/env elixir

# Test the enhanced pattern flow

# Simulate the format_ast_enhanced_pattern function from the controller
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

# Simulate an enhanced pattern
enhanced_pattern_map = %{
  id: "js-sql-injection-concat",
  name: "SQL Injection via String Concatenation",
  description: "Detects SQL query construction using string concatenation with user input",
  type: :sql_injection,
  severity: :critical,
  languages: ["javascript", "typescript"],
  regex: ~r/SELECT.*FROM.*WHERE/i,
  cwe_id: "CWE-89",
  owasp_category: "A03:2021",
  recommendation: "Use parameterized queries",
  test_cases: %{
    vulnerable: ["db.query('SELECT * FROM users WHERE id = ' + userId)"],
    safe: ["db.query('SELECT * FROM users WHERE id = ?', [userId])"]
  },
  # AST enhancement fields
  ast_rules: %{
    node_type: "BinaryExpression",
    operator: "+",
    context_analysis: %{
      contains_sql_keywords: true,
      has_user_input_in_concatenation: true,
      within_db_call: true
    }
  },
  context_rules: %{
    exclude_paths: [~r/test/, ~r/spec/],
    exclude_if_parameterized: true
  },
  confidence_rules: %{
    base: 0.3,
    adjustments: %{
      "direct_req_param_concat" => 0.5,
      "within_db_query_call" => 0.3
    }
  },
  min_confidence: 0.8
}

IO.puts("Enhanced pattern keys BEFORE format_ast_enhanced_pattern:")
IO.inspect(Map.keys(enhanced_pattern_map) |> Enum.sort())

# Apply the formatting
formatted = format_ast_enhanced_pattern.(enhanced_pattern_map)

IO.puts("\nFormatted pattern keys AFTER format_ast_enhanced_pattern:")
IO.inspect(Map.keys(formatted) |> Enum.sort())

IO.puts("\nMissing AST enhancement fields:")
missing = [:ast_rules, :context_rules, :confidence_rules, :min_confidence]
  |> Enum.filter(fn key -> not Map.has_key?(formatted, key) end)
IO.inspect(missing)

IO.puts("\nThe issue: format_ast_enhanced_pattern doesn't preserve AST enhancement fields!")
IO.puts("It needs to be updated to include these fields in the output.")