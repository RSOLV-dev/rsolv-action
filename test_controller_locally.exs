#!/usr/bin/env elixir

# Start the app and test the controller logic directly
Code.require_file("test/support/conn_case.ex")
Code.require_file("test/support/data_case.ex")

defmodule TestControllerLocally do
  use RSOLVWeb.ConnCase
  
  alias RSOLVWeb.Api.V1.PatternController
  alias RsolvApi.Security.{Pattern, DemoPatterns, ASTPattern}
  alias RSOLVApi.Security.Patterns.JSONSerializer
  
  def run do
    IO.puts("\n🔍 Testing Controller Logic Locally\n")
    
    # Test getting demo patterns
    patterns = DemoPatterns.get_demo_patterns("javascript")
    IO.puts("Demo patterns: #{length(patterns)}")
    
    # Test formatting a single pattern
    pattern = List.first(patterns)
    IO.puts("\nTesting pattern: #{pattern.id}")
    
    # Test standard format
    try do
      formatted = format_pattern_without_tier(pattern, :standard)
      IO.puts("✅ Standard format OK")
    rescue
      e ->
        IO.puts("❌ Standard format failed: #{Exception.message(e)}")
    end
    
    # Test enhanced format
    try do
      formatted = format_pattern_without_tier(pattern, :enhanced)
      IO.puts("✅ Enhanced format OK")
      IO.puts("  Has ast_rules: #{Map.has_key?(formatted, :ast_rules)}")
      
      # Test JSON encoding
      response_data = %{
        patterns: [formatted],
        metadata: %{
          language: "javascript",
          format: "enhanced",
          count: 1
        }
      }
      
      json_data = JSONSerializer.encode!(response_data)
      IO.puts("✅ JSON encoding OK (#{byte_size(json_data)} bytes)")
      
    rescue
      e ->
        IO.puts("❌ Enhanced format failed: #{Exception.message(e)}")
        IO.inspect(e, label: "Full error")
    end
  end
  
  # Copy the function from the controller
  defp format_pattern_without_tier(%Pattern{} = pattern, format) do
    base_format = Pattern.to_api_format(pattern)
    
    # Remove tier field
    formatted = Map.delete(base_format, :tier)
    
    # Add enhanced fields if requested
    if format == :enhanced do
      # Get the pattern module from pattern ID
      pattern_module = pattern_id_to_module(pattern.id)
      
      # Check if module has ast_enhancement/0
      if pattern_module && function_exported?(pattern_module, :ast_enhancement, 0) do
        try do
          # Get enhancement data from the pattern module
          enhancement = apply(pattern_module, :ast_enhancement, [])
          
          # Add enhancement fields directly to the pattern
          formatted
          |> Map.put(:ast_rules, enhancement[:ast_rules])
          |> Map.put(:context_rules, enhancement[:context_rules])
          |> Map.put(:confidence_rules, enhancement[:confidence_rules])
          |> Map.put(:min_confidence, enhancement[:min_confidence])
        rescue
          _ -> formatted
        end
      else
        # No module found - use ASTPattern.enhance for demo patterns
        try do
          IO.puts("  Using ASTPattern.enhance...")
          
          ast_pattern = ASTPattern.enhance(pattern)
          
          formatted
          |> Map.put(:ast_rules, ast_pattern.ast_rules)
          |> Map.put(:context_rules, ast_pattern.context_rules)
          |> Map.put(:confidence_rules, ast_pattern.confidence_rules)
          |> Map.put(:min_confidence, ast_pattern.min_confidence)
        rescue
          e ->
            IO.puts("  Failed to enhance: #{Exception.message(e)}")
            formatted
        end
      end
    else
      formatted
    end
  end
  
  defp pattern_id_to_module(pattern_id) do
    parts = String.split(pattern_id, "-")
    
    if length(parts) >= 2 do
      [lang | rest] = parts
      
      language = case lang do
        "js" -> "Javascript"
        "ts" -> "Typescript"
        "py" -> "Python"
        "rb" -> "Ruby"
        "php" -> "Php"
        "go" -> "Go"
        "java" -> "Java"
        _ -> String.capitalize(lang)
      end
      
      pattern_name = rest
        |> Enum.map(&String.capitalize/1)
        |> Enum.join("")
      
      module_name = Module.concat([
        RsolvApi.Security.Patterns,
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

# Run in test environment
Mix.env(:test)
TestControllerLocally.run()