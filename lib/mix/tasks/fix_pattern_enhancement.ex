defmodule Mix.Tasks.FixPatternEnhancement do
  use Mix.Task

  @shortdoc "Fix pattern controller to properly include AST enhancement data"

  def run(_) do
    Mix.Task.run("compile")

    IO.puts("\n🔧 Fixing Pattern Enhancement Loading\n")

    # First, let's verify the issue
    IO.puts("1️⃣ Current situation:")

    # Load a pattern the current way
    patterns = Rsolv.Security.Patterns.Javascript.all()
    eval_pattern = Enum.find(patterns, &(&1.id == "js-eval-user-input"))

    if eval_pattern do
      IO.puts("   Found pattern: #{eval_pattern.id}")

      # Check if the pattern module has ast_enhancement
      module_name = pattern_id_to_module(eval_pattern.id)
      IO.puts("   Module: #{inspect(module_name)}")

      if module_name && function_exported?(module_name, :ast_enhancement, 0) do
        IO.puts("   Has ast_enhancement/0: ✅")

        enhancement = apply(module_name, :ast_enhancement, [])
        IO.puts("   AST rules: #{map_size(enhancement.ast_rules)} rules")
        IO.puts("   Context rules: #{map_size(enhancement.context_rules)} rules")
        IO.puts("   Min confidence: #{enhancement.min_confidence}")
      else
        IO.puts("   Has ast_enhancement/0: ❌")
      end
    end

    IO.puts("\n2️⃣ Proposed fix:")
    IO.puts("   The pattern controller should:")
    IO.puts("   - Check if pattern module has ast_enhancement/0")
    IO.puts("   - Call it to get enhancement data")
    IO.puts("   - Include the data in enhanced format response")
    IO.puts("   - Use JSONSerializer to handle regex serialization")

    IO.puts("\n3️⃣ Implementation needed in pattern_controller.ex:")

    IO.puts("""

    defp format_pattern_without_tier(%Pattern{} = pattern, :enhanced) do
      base_format = Pattern.to_api_format(pattern)
      |> Map.delete(:tier)

      # Get enhancement from pattern module
      pattern_module = pattern_id_to_module(pattern.id)

      if pattern_module && function_exported?(pattern_module, :ast_enhancement, 0) do
        enhancement = apply(pattern_module, :ast_enhancement, [])

        base_format
        |> Map.put(:ast_rules, enhancement[:ast_rules])
        |> Map.put(:context_rules, enhancement[:context_rules])
        |> Map.put(:confidence_rules, enhancement[:confidence_rules])
        |> Map.put(:min_confidence, enhancement[:min_confidence])
      else
        base_format
      end
    end
    """)
  end

  defp pattern_id_to_module(pattern_id) do
    # Convert pattern ID to module name
    # e.g., "js-eval-user-input" -> Rsolv.Security.Patterns.Javascript.EvalUserInput
    parts = String.split(pattern_id, "-")

    if length(parts) >= 2 do
      [lang | rest] = parts

      language =
        case lang do
          "js" -> "Javascript"
          "py" -> "Python"
          "rb" -> "Ruby"
          _ -> String.capitalize(lang)
        end

      pattern_name =
        rest
        |> Enum.map(&String.capitalize/1)
        |> Enum.join("")

      module_name = "Elixir.Rsolv.Security.Patterns.#{language}.#{pattern_name}"

      try do
        String.to_existing_atom(module_name)
      rescue
        _ -> nil
      end
    else
      nil
    end
  end
end
