defmodule Rsolv.AST.ASTPatternMatcherFix do
  @moduledoc """
  Test fix for AST pattern matching with proper op handling
  """

  def test_pattern_match do
    # Python SQL injection pattern
    pattern = %{
      "type" => "BinOp",
      "op" => "Add"
    }

    # Python AST node
    node = %{
      "type" => "BinOp",
      "op" => %{"type" => "Add"},
      "left" => %{"type" => "Constant", "value" => "SELECT * FROM users WHERE id = "},
      "right" => %{"type" => "Name", "id" => "user_id"}
    }

    IO.puts("Testing pattern match...")
    IO.puts("Pattern: #{inspect(pattern)}")
    IO.puts("Node: #{inspect(node, limit: 2)}")

    # Test each field
    type_match = node["type"] == pattern["type"]
    IO.puts("\nType match: #{type_match}")

    # Test op matching
    op_match = matches_op_value?(node["op"], pattern["op"])
    IO.puts("Op match: #{op_match}")

    overall_match = type_match && op_match
    IO.puts("\nOverall match: #{overall_match}")
  end

  defp matches_op_value?(actual, expected) when is_map(actual) and is_binary(expected) do
    # Handle Python operator nodes like %{"type" => "Add"}
    actual["type"] == expected
  end

  defp matches_op_value?(actual, expected) do
    actual == expected
  end
end
