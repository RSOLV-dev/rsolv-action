# credo:disable-for-this-file Credo.Check.Warning.IoInspect
#!/usr/bin/env elixir

Mix.Task.run("compile")

# Test the exact code path that's failing

defmodule DebugEnhancedError do
  def run do
    IO.puts("\n🔍 Debugging Enhanced Format Error\n")

    # Simulate the controller flow
    alias Rsolv.Security.{Pattern, DemoPatterns, ASTPattern}
    alias RSOLVApi.Security.Patterns.JSONSerializer

    # Get demo patterns (what happens without auth)
    patterns = DemoPatterns.get_demo_patterns("javascript")
    IO.puts("Got #{length(patterns)} demo patterns")

    # Test formatting each pattern
    Enum.each(patterns, fn pattern ->
      IO.puts("\nTesting pattern: #{pattern.id}")

      try do
        # Format without tier (standard)
        formatted = Pattern.to_api_format(pattern) |> Map.delete(:tier)
        IO.puts("  ✅ Standard format OK")

        # Try enhanced format
        pattern_module = find_module(pattern.id)
        IO.puts("  Module found: #{inspect(pattern_module)}")

        enhanced =
          if pattern_module && function_exported?(pattern_module, :ast_enhancement, 0) do
            enhancement = apply(pattern_module, :ast_enhancement, [])

            formatted
            |> Map.put(:ast_rules, enhancement[:ast_rules])
            |> Map.put(:context_rules, enhancement[:context_rules])
            |> Map.put(:confidence_rules, enhancement[:confidence_rules])
            |> Map.put(:min_confidence, enhancement[:min_confidence])
          else
            # Use ASTPattern.enhance
            ast_pattern = ASTPattern.enhance(pattern)

            formatted
            |> Map.put(:ast_rules, ast_pattern.ast_rules)
            |> Map.put(:context_rules, ast_pattern.context_rules)
            |> Map.put(:confidence_rules, ast_pattern.confidence_rules)
            |> Map.put(:min_confidence, ast_pattern.min_confidence)
          end

        IO.puts("  ✅ Enhanced format OK")

        # Test JSON serialization
        response_data = %{
          patterns: [enhanced],
          metadata: %{
            language: "javascript",
            format: "enhanced",
            count: 1
          }
        }

        json_data = JSONSerializer.encode!(response_data)
        IO.puts("  ✅ JSON serialization OK (#{byte_size(json_data)} bytes)")
      rescue
        e ->
          IO.puts("  ❌ Error: #{Exception.message(e)}")
          IO.puts("  Type: #{inspect(e.__struct__)}")
          IO.inspect(Exception.format_stacktrace(), label: "  Stack", limit: 5)
      end
    end)
  end

  defp find_module(pattern_id) do
    parts = String.split(pattern_id, "-")

    if length(parts) >= 2 do
      [lang | rest] = parts

      language =
        case lang do
          "js" -> "Javascript"
          _ -> String.capitalize(lang)
        end

      pattern_name =
        rest
        |> Enum.map(&String.capitalize/1)
        |> Enum.join("")

      module_name =
        Module.concat([
          Rsolv.Security.Patterns,
          language,
          pattern_name
        ])

      if Code.ensure_loaded?(module_name) do
        module_name
      else
        nil
      end
    else
      nil
    end
  end
end

DebugEnhancedError.run()
