#!/usr/bin/env elixir

# TDD RED Phase: Debug AST Pattern Matching
# 
# This test aims to understand why the AST pattern matcher is not detecting
# vulnerabilities despite the infrastructure being fully operational.
#
# Expected: This test should FAIL, showing us exactly where pattern matching breaks

Mix.install([
  {:jason, "~> 1.4"}
])

defmodule ASTPatternMatcherDebugTest do
  @doc """
  TDD RED Phase: Test the AST pattern matching logic directly
  
  This should reveal why vulnerabilities are not being detected
  despite having working AST parsing and pattern loading.
  """
  
  def run_debug_test do
    IO.puts("🔴 TDD RED Phase: AST Pattern Matching Debug")
    IO.puts("=" |> String.duplicate(50))
    
    # Test 1: Simple Python SQL injection case
    test_python_sql_injection()
    
    # Test 2: JavaScript SQL injection case  
    test_javascript_sql_injection()
    
    # Test 3: Pattern structure verification
    test_pattern_structure()
    
    IO.puts("\n📋 Summary:")
    IO.puts("These tests should help us identify where pattern matching fails")
  end
  
  defp test_python_sql_injection do
    IO.puts("\n🧪 Test 1: Python SQL Injection Pattern Matching")
    
    # Simple test case that should match
    python_ast_node = %{
      "type" => "BinOp",
      "op" => %{"type" => "Add"},
      "left" => %{
        "type" => "Constant", 
        "value" => "SELECT * FROM users WHERE id = "
      },
      "right" => %{
        "type" => "Name",
        "id" => "user_id"
      }
    }
    
    # Expected pattern structure for Python SQL injection
    pattern = %{
      id: "python-sql-injection",
      name: "SQL Injection via String Concatenation",
      ast_rules: %{
        node_type: "BinOp",
        op: "Add",  # This should match %{"type" => "Add"} via our special handling
        sql_context: %{
          left_contains_sql: true
        }
      }
    }
    
    IO.puts("   AST Node: #{inspect(python_ast_node, pretty: true)}")
    IO.puts("   Pattern: #{inspect(pattern, pretty: true)}")
    
    # Test the matching logic
    # Note: We can't easily test this without loading the full module
    # But we can test the specific matching function
    
    test_operator_matching(python_ast_node["op"], pattern.ast_rules.op)
    test_node_type_matching(python_ast_node["type"], pattern.ast_rules.node_type)
  end
  
  defp test_javascript_sql_injection do
    IO.puts("\n🧪 Test 2: JavaScript SQL Injection Pattern Matching")
    
    javascript_ast_node = %{
      "type" => "BinaryExpression",
      "operator" => "+",
      "left" => %{
        "type" => "Literal",
        "value" => "SELECT * FROM users WHERE id = "
      },
      "right" => %{
        "type" => "Identifier", 
        "name" => "userId"
      }
    }
    
    pattern = %{
      id: "javascript-sql-injection",
      name: "SQL Injection via String Concatenation",
      ast_rules: %{
        node_type: "BinaryExpression",
        operator: "+"
      }
    }
    
    IO.puts("   AST Node: #{inspect(javascript_ast_node, pretty: true)}")
    IO.puts("   Pattern: #{inspect(pattern, pretty: true)}")
    
    test_operator_matching(javascript_ast_node["operator"], pattern.ast_rules.operator)
    test_node_type_matching(javascript_ast_node["type"], pattern.ast_rules.node_type)
  end
  
  defp test_pattern_structure do
    IO.puts("\n🧪 Test 3: Pattern Structure Verification")
    
    # Load an actual pattern to see its structure
    IO.puts("   Loading actual patterns from the system...")
    
    # This will likely fail, showing us what patterns actually look like
    try do
      # Try to call the pattern loading system
      IO.puts("   TODO: Load actual patterns and inspect their structure")
      IO.puts("   Expected: This should show us the real pattern format")
    rescue
      error ->
        IO.puts("   ❌ Pattern loading failed: #{inspect(error)}")
        IO.puts("   This indicates we need to load patterns differently for testing")
    end
  end
  
  defp test_operator_matching(actual_op, expected_op) do
    IO.puts("   🔍 Testing operator matching:")
    IO.puts("      Actual: #{inspect(actual_op)}")
    IO.puts("      Expected: #{inspect(expected_op)}")
    
    # Test our special matching logic for Python operators
    result = case {actual_op, expected_op} do
      {%{"type" => op_type}, expected_op} when is_binary(expected_op) ->
        match_result = op_type == expected_op
        IO.puts("      Python operator match: #{match_result} (#{op_type} == #{expected_op})")
        match_result
      {actual, expected} ->
        match_result = actual == expected
        IO.puts("      Direct match: #{match_result} (#{actual} == #{expected})")
        match_result
    end
    
    if result do
      IO.puts("      ✅ Operator matching works")
    else
      IO.puts("      ❌ Operator matching failed - THIS IS THE ISSUE")
    end
  end
  
  defp test_node_type_matching(actual_type, expected_type) do
    IO.puts("   🔍 Testing node type matching:")
    IO.puts("      Actual: #{inspect(actual_type)}")
    IO.puts("      Expected: #{inspect(expected_type)}")
    
    result = actual_type == expected_type
    
    if result do
      IO.puts("      ✅ Node type matching works")
    else
      IO.puts("      ❌ Node type matching failed - THIS IS THE ISSUE")
    end
  end
end

# Run the debug test
ASTPatternMatcherDebugTest.run_debug_test()