# Fix to make PatternAdapter use PatternServer instead of PatternRegistry
IO.puts("🔧 Testing Pattern Loading Fix")
IO.puts("=" <> String.duplicate("=", 60))

# Define a fixed version that uses PatternServer
defmodule PatternAdapterFix do
  alias Rsolv.Security.{PatternServer, ASTPattern}
  alias Rsolv.AST.PatternAdapter
  require Logger

  def load_patterns_for_language(language) do
    # Get patterns from PatternServer instead of PatternRegistry
    patterns =
      case PatternServer.get_patterns(language) do
        {:ok, patterns} -> patterns
        _ -> []
      end

    Logger.info(
      "PatternAdapterFix loading patterns for #{language}: found #{length(patterns)} patterns"
    )

    # Enhance and convert patterns
    patterns
    |> Enum.map(&PatternAdapter.enhance_pattern/1)
    |> Enum.map(&PatternAdapter.convert_to_matcher_format/1)
    |> Enum.reject(&is_nil/1)
  end
end

# Test the fix
IO.puts("\n1. Testing original PatternAdapter:")
original = Rsolv.AST.PatternAdapter.load_patterns_for_language("python")
IO.puts("   Loaded #{length(original)} patterns")

IO.puts("\n2. Testing fixed version:")
fixed = PatternAdapterFix.load_patterns_for_language("python")
IO.puts("   Loaded #{length(fixed)} patterns")

if length(fixed) > 0 do
  sql_pattern = Enum.find(fixed, fn p -> String.contains?(p.id || "", "sql") end)

  if sql_pattern do
    IO.puts("\n3. Found SQL pattern:")
    IO.puts("   ID: #{sql_pattern.id}")
    IO.puts("   Has ast_pattern? #{not is_nil(sql_pattern[:ast_pattern])}")

    if sql_pattern[:ast_pattern] do
      IO.puts("   AST pattern: #{inspect(sql_pattern[:ast_pattern])}")
    end
  end
end
