defmodule Rsolv.AST.DebugPatternMatcher do
  @moduledoc """
  Debug version of pattern matcher to understand why patterns aren't matching
  """
  
  def debug_match(node, pattern) do
    IO.puts("\n=== DEBUG Pattern Matching ===")
    IO.puts("Node type: #{inspect(node["type"])}")
    IO.puts("Pattern type: #{inspect(pattern["type"])}")
    
    Enum.each(pattern, fn {key, expected} ->
      if String.starts_with?(to_string(key), "_") do
        IO.puts("Skipping context key: #{key}")
      else
        actual = node[key]
        matches = matches_value?(actual, expected)
        IO.puts("\nField '#{key}':")
        IO.puts("  Expected: #{inspect(expected)}")
        IO.puts("  Actual: #{inspect(actual)}")
        IO.puts("  Matches: #{matches}")
      end
    end)
  end
  
  defp matches_value?(actual, expected) when is_map(actual) and is_binary(expected) do
    # Special case for Python operators
    case actual do
      %{"type" => op_type} -> op_type == expected
      _ -> false
    end
  end
  
  defp matches_value?(actual, expected) do
    actual == expected
  end
end