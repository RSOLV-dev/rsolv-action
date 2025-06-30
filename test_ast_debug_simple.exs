#!/usr/bin/env elixir

# Simple script to debug AST pattern matching without full test infrastructure
# RED Phase: Identify exactly where pattern matching breaks down

Mix.install([])

# Load the modules we need to test
Code.require_file("lib/rsolv_api/security/patterns/pattern_base.ex")
Code.require_file("lib/rsolv_api/security/pattern.ex")
Code.require_file("lib/rsolv_api/security/patterns/python/sql_injection_concat.ex")

alias RsolvApi.Security.Patterns.Python.SqlInjectionConcat

IO.puts("=== RED Phase: AST Pattern Matching Debug ===\n")

# Test 1: Check what the pattern expects
IO.puts("1. Pattern Structure Analysis:")
pattern = SqlInjectionConcat.pattern()
IO.inspect(pattern.id, label: "Pattern ID")
IO.inspect(pattern.type, label: "Pattern Type")

enhancement = SqlInjectionConcat.ast_enhancement()
IO.inspect(enhancement, label: "AST Enhancement", pretty: true)

ast_rules = enhancement.ast_rules
IO.puts("\nAST Rules Expected:")
IO.inspect(ast_rules.node_type, label: "Expected Node Type")

if Map.has_key?(ast_rules, :operator) do
  IO.inspect(ast_rules.operator, label: "Expected Operator")
end

if Map.has_key?(ast_rules, :op) do
  IO.inspect(ast_rules.op, label: "Expected Op")
end

if Map.has_key?(ast_rules, :sql_context) do
  IO.inspect(ast_rules.sql_context, label: "SQL Context Requirements")
end

# Test 2: Simulate what Python AST parser should produce
IO.puts("\n2. Expected Python AST Structure:")
IO.puts("For code: query = \"SELECT * FROM users WHERE id = \" + user_id")

expected_python_ast = %{
  "type" => "Module",
  "body" => [
    %{
      "type" => "Assign",
      "targets" => [%{"type" => "Name", "id" => "query"}],
      "value" => %{
        "type" => "BinOp",
        "left" => %{"type" => "Constant", "value" => "SELECT * FROM users WHERE id = "},
        "op" => %{"type" => "Add"},
        "right" => %{"type" => "Name", "id" => "user_id"}
      }
    }
  ]
}

IO.inspect(expected_python_ast, label: "Expected Python AST", pretty: true)

# Test 3: Check JavaScript pattern for comparison
Code.require_file("lib/rsolv_api/security/patterns/javascript/sql_injection_concat.ex")
alias RsolvApi.Security.Patterns.Javascript.SqlInjectionConcat, as: JsSqlPattern

IO.puts("\n3. JavaScript Pattern Comparison:")
js_pattern = JsSqlPattern.pattern()
js_enhancement = JsSqlPattern.ast_enhancement()

IO.inspect(js_enhancement.ast_rules.node_type, label: "JS Expected Node Type")

if Map.has_key?(js_enhancement.ast_rules, :operator) do
  IO.inspect(js_enhancement.ast_rules.operator, label: "JS Expected Operator")
end

# Test 4: Identify the mismatch
IO.puts("\n4. Potential Mismatch Analysis:")
IO.puts("Python pattern expects: #{ast_rules.node_type}")
IO.puts("JavaScript pattern expects: #{js_enhancement.ast_rules.node_type}")

IO.puts("\nPython AST produces operator: %{\"type\" => \"Add\"}")
IO.puts("JavaScript AST produces operator: \"+\"")

IO.puts("\n=== Key Findings ===")
IO.puts("1. Python and JavaScript use different AST structures")
IO.puts("2. Python: BinOp with op: %{\"type\" => \"Add\"}")  
IO.puts("3. JavaScript: BinaryExpression with operator: \"+\"")
IO.puts("4. Patterns might expect different operator formats")

IO.puts("\n=== Next Steps for GREEN Phase ===")
IO.puts("1. Check if SecurityPatternMatcher handles both operator formats")
IO.puts("2. Verify operator normalization in pattern matching")
IO.puts("3. Test confidence calculation and thresholds")
IO.puts("4. Debug context rule application")