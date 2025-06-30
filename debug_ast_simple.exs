#!/usr/bin/env elixir

# Simple debug script to test AST detection
IO.puts("\n=== Testing AST Pattern Detection ===\n")

# 1. Test pattern loading
alias RsolvApi.Security.PatternRegistry
alias RsolvApi.AST.PatternAdapter

IO.puts("1. Loading patterns...")
js_patterns = PatternRegistry.get_patterns_for_language("javascript")
IO.puts("   JavaScript patterns: #{length(js_patterns)}")

sql_patterns = Enum.filter(js_patterns, &String.contains?(&1.id, "sql"))
IO.puts("   SQL patterns: #{Enum.map(sql_patterns, & &1.id) |> inspect()}")

# 2. Test pattern adapter
IO.puts("\n2. Testing pattern adapter...")
adapted = PatternAdapter.load_patterns_for_language("javascript")
IO.puts("   Adapted patterns: #{length(adapted)}")

sql_adapted = Enum.filter(adapted, &String.contains?(&1.id, "sql-injection-concat"))
if length(sql_adapted) > 0 do
  pattern = List.first(sql_adapted)
  IO.puts("   SQL injection pattern AST rules:")
  IO.inspect(pattern.ast_pattern, pretty: true, limit: :infinity)
end

# 3. Test actual AST structure from parser
IO.puts("\n3. Checking what parser returns...")
test_ast = %{
  "type" => "Program",
  "body" => [
    %{
      "type" => "FunctionDeclaration",
      "id" => %{"type" => "Identifier", "name" => "handleRequest"},
      "params" => [%{"type" => "Identifier", "name" => "userInput"}],
      "body" => %{
        "type" => "BlockStatement",
        "body" => [
          %{
            "type" => "VariableDeclaration",
            "declarations" => [
              %{
                "type" => "VariableDeclarator",
                "id" => %{"type" => "Identifier", "name" => "query"},
                "init" => %{
                  "type" => "BinaryExpression",
                  "operator" => "+",
                  "left" => %{
                    "type" => "Literal",
                    "value" => "SELECT * FROM users WHERE id = "
                  },
                  "right" => %{"type" => "Identifier", "name" => "userInput"}
                }
              }
            ]
          }
        ]
      }
    }
  ]
}

IO.puts("   Test AST contains BinaryExpression: #{inspect(test_ast |> Jason.encode!() |> String.contains?("BinaryExpression"))}")

# 4. Test pattern matching directly
alias RsolvApi.AST.ASTPatternMatcher

if length(adapted) > 0 do
  IO.puts("\n4. Testing pattern matching...")
  {:ok, matches} = ASTPatternMatcher.match_multiple(test_ast, adapted, "javascript")
  IO.puts("   Matches found: #{length(matches)}")
  
  if length(matches) == 0 && length(sql_adapted) > 0 do
    # Debug why it's not matching
    pattern = List.first(sql_adapted)
    IO.puts("\n   Debugging SQL pattern match...")
    
    # Check if the pattern structure is correct
    IO.puts("   Pattern expects node type: #{inspect(pattern.ast_pattern["type"])}")
    IO.puts("   Pattern expects operator: #{inspect(pattern.ast_pattern["operator"])}")
    
    # Test matching just the BinaryExpression node
    binary_expr = %{
      "type" => "BinaryExpression",
      "operator" => "+",
      "left" => %{
        "type" => "Literal",
        "value" => "SELECT * FROM users WHERE id = "
      },
      "right" => %{"type" => "Identifier", "name" => "userInput"}
    }
    
    IO.puts("\n   Testing if BinaryExpression matches pattern...")
    matches_pattern = ASTPatternMatcher.matches_pattern?(binary_expr, pattern.ast_pattern)
    IO.puts("   Direct pattern match: #{matches_pattern}")
    
    if !matches_pattern do
      IO.puts("\n   Pattern structure:")
      IO.inspect(pattern.ast_pattern, pretty: true)
      IO.puts("\n   Node structure:")
      IO.inspect(binary_expr, pretty: true)
    end
  end
end

IO.puts("\n=== DONE ===")