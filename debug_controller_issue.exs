#!/usr/bin/env elixir

Mix.Task.run("app.start")

defmodule DebugControllerIssue do
  alias RsolvApi.Security.Pattern
  alias RsolvApi.Security.DemoPatterns
  alias RSOLVApi.Security.Patterns.JSONSerializer
  
  def run do
    IO.puts("\n🔍 Debugging Controller Issue\n")
    
    # Get a demo pattern
    patterns = DemoPatterns.get_demo_patterns("javascript")
    pattern = List.first(patterns)
    
    IO.puts("1️⃣ Demo pattern:")
    IO.puts("   ID: #{pattern.id}")
    IO.puts("   Type: #{inspect(pattern.__struct__)}")
    
    # Test to_api_format
    IO.puts("\n2️⃣ Testing Pattern.to_api_format:")
    try do
      api_format = Pattern.to_api_format(pattern)
      IO.puts("   ✅ Success")
      IO.puts("   Keys: #{inspect(Map.keys(api_format))}")
    rescue
      e ->
        IO.puts("   ❌ Failed: #{inspect(e)}")
        IO.puts("   Message: #{Exception.message(e)}")
    end
    
    # Test pattern_id_to_module
    IO.puts("\n3️⃣ Testing pattern_id_to_module:")
    module = pattern_id_to_module(pattern.id)
    IO.puts("   Pattern ID: #{pattern.id}")
    IO.puts("   Module found: #{inspect(module)}")
    
    # Test full formatting
    IO.puts("\n4️⃣ Testing full format_pattern_without_tier:")
    try do
      formatted = format_pattern_without_tier(pattern, :enhanced)
      IO.puts("   ✅ Formatting successful")
      IO.puts("   Has ast_rules: #{Map.has_key?(formatted, :ast_rules)}")
      
      # Test JSONSerializer
      IO.puts("\n5️⃣ Testing JSONSerializer:")
      response_data = %{
        patterns: [formatted],
        metadata: %{
          language: "javascript",
          format: "enhanced",
          count: 1
        }
      }
      
      json_data = JSONSerializer.encode!(response_data)
      IO.puts("   ✅ JSON encoding successful")
      IO.puts("   Size: #{byte_size(json_data)} bytes")
      
    rescue
      e ->
        IO.puts("   ❌ Failed: #{inspect(e)}")
        IO.puts("   Message: #{Exception.message(e)}")
        IO.inspect(Exception.format_stacktrace(), label: "Stacktrace")
    end
  end
  
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
        # No module found - try using ASTPattern.enhance
        IO.puts("   No module found, trying ASTPattern.enhance...")
        try do
          ast_pattern = RsolvApi.Security.ASTPattern.enhance(pattern)
          
          formatted
          |> Map.put(:ast_rules, ast_pattern.ast_rules)
          |> Map.put(:context_rules, ast_pattern.context_rules)
          |> Map.put(:confidence_rules, ast_pattern.confidence_rules)
          |> Map.put(:min_confidence, ast_pattern.min_confidence)
        rescue
          _ -> formatted
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

DebugControllerIssue.run()