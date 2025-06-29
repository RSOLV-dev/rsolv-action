#!/usr/bin/env elixir

# Debug the enhanced API issue

Mix.Task.run("app.start")

alias RsolvApi.Security.ASTPattern
alias RsolvApi.Security.DemoPatterns
alias RSOLVApi.Security.Patterns.JSONSerializer

defmodule DebugEnhancedAPI do
  def run do
    IO.puts("\n🔍 Debugging Enhanced API Issue\n")
    
    # Test getting demo patterns
    IO.puts("1️⃣ Testing DemoPatterns.get_demo_patterns:")
    patterns = DemoPatterns.get_demo_patterns("javascript")
    IO.puts("   Pattern count: #{length(patterns)}")
    
    if length(patterns) > 0 do
      pattern = List.first(patterns)
      IO.puts("   First pattern ID: #{pattern.id}")
      
      # Test formatting without tier
      IO.puts("\n2️⃣ Testing format_pattern_without_tier:")
      formatted = format_pattern_without_tier(pattern, :enhanced)
      IO.puts("   Formatted keys: #{inspect(Map.keys(formatted))}")
      IO.puts("   Has ast_rules: #{Map.has_key?(formatted, :ast_rules)}")
      
      # Test JSON serialization
      IO.puts("\n3️⃣ Testing JSONSerializer:")
      try do
        json_data = JSONSerializer.encode!(formatted)
        IO.puts("   ✅ Serialization successful")
      rescue
        e ->
          IO.puts("   ❌ Serialization failed: #{inspect(e)}")
          IO.puts("   Error: #{Exception.message(e)}")
      end
    end
    
    # Test with ASTPattern
    IO.puts("\n4️⃣ Testing ASTPattern.get_all_patterns_for_language:")
    try do
      ast_patterns = ASTPattern.get_all_patterns_for_language("javascript", :enhanced)
      IO.puts("   Pattern count: #{length(ast_patterns)}")
    rescue
      e ->
        IO.puts("   ❌ Failed: #{inspect(e)}")
    end
  end
  
  defp format_pattern_without_tier(%RsolvApi.Security.Pattern{} = pattern, format) do
    base_format = RsolvApi.Security.Pattern.to_api_format(pattern)
    
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
        formatted
      end
    else
      formatted
    end
  end
  
  defp pattern_id_to_module(pattern_id) do
    # Convert pattern ID to module name
    # e.g., "js-xss-dom-manipulation" -> RsolvApi.Security.Patterns.Javascript.XssDomManipulation
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

DebugEnhancedAPI.run()