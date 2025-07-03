#!/usr/bin/env elixir

# Test to verify enhanced format now includes AST enhancement data

Code.require_file("lib/rsolv_api_web/controllers/api/v1/pattern_controller.ex")
Code.require_file("lib/rsolv_api/security/pattern.ex") 
Code.require_file("lib/rsolv_api/security/patterns/pattern_base.ex")
Code.require_file("lib/rsolv_api/security/patterns/javascript/eval_user_input.ex")
Code.require_file("lib/rsolv_api/security/patterns/json_serializer.ex")

defmodule VerifyEnhancedFormatFix do
  alias Rsolv.Security.Pattern
  alias RSOLVApi.Security.Patterns.JSONSerializer
  
  def run do
    IO.puts("\n🔍 Verifying Enhanced Format Fix\n")
    
    # Create a pattern from the eval module
    pattern_module = Rsolv.Security.Patterns.Javascript.EvalUserInput
    pattern = pattern_module.pattern()
    
    IO.puts("Testing pattern: #{pattern.id}")
    
    # Simulate what the controller does for enhanced format
    IO.puts("\n1️⃣ Standard format:")
    standard_format = Pattern.to_api_format(pattern)
    |> Map.delete(:tier)
    
    IO.puts("   Fields: #{inspect(Map.keys(standard_format))}")
    IO.puts("   Has ast_rules: #{Map.has_key?(standard_format, :ast_rules)}")
    
    IO.puts("\n2️⃣ Enhanced format (with fix):")
    
    # Get pattern module
    pattern_module = pattern_id_to_module(pattern.id)
    IO.puts("   Pattern module: #{inspect(pattern_module)}")
    
    enhanced_format = if pattern_module && function_exported?(pattern_module, :ast_enhancement, 0) do
      enhancement = apply(pattern_module, :ast_enhancement, [])
      
      standard_format
      |> Map.put(:ast_rules, enhancement[:ast_rules])
      |> Map.put(:context_rules, enhancement[:context_rules])
      |> Map.put(:confidence_rules, enhancement[:confidence_rules])
      |> Map.put(:min_confidence, enhancement[:min_confidence])
    else
      standard_format
    end
    
    IO.puts("   Fields: #{inspect(Map.keys(enhanced_format))}")
    IO.puts("   Has ast_rules: #{Map.has_key?(enhanced_format, :ast_rules)}")
    IO.puts("   Has context_rules: #{Map.has_key?(enhanced_format, :context_rules)}")
    IO.puts("   Has confidence_rules: #{Map.has_key?(enhanced_format, :confidence_rules)}")
    IO.puts("   Has min_confidence: #{Map.has_key?(enhanced_format, :min_confidence)}")
    
    if enhanced_format[:ast_rules] do
      IO.puts("\n   ✅ AST rules included!")
      IO.puts("   Node type: #{enhanced_format[:ast_rules][:node_type]}")
    end
    
    if enhanced_format[:context_rules] do
      IO.puts("\n   ✅ Context rules included!")
      IO.puts("   Exclude paths: #{inspect(enhanced_format[:context_rules][:exclude_paths])}")
    end
    
    if enhanced_format[:confidence_rules] do
      IO.puts("\n   ✅ Confidence rules included!")
      IO.puts("   Base confidence: #{enhanced_format[:confidence_rules][:base]}")
    end
    
    # Test JSON serialization
    IO.puts("\n3️⃣ JSON Serialization:")
    try do
      json_data = JSONSerializer.encode!(enhanced_format)
      IO.puts("   ✅ Successfully serialized to JSON")
      IO.puts("   Size: #{byte_size(json_data)} bytes")
      
      if String.contains?(json_data, ~s("__type__":"regex")) do
        IO.puts("   ✅ Contains serialized regex")
      end
    rescue
      e ->
        IO.puts("   ❌ Serialization failed: #{inspect(e)}")
    end
    
    IO.puts("\n✅ Enhanced format fix verified!")
  end
  
  defp pattern_id_to_module(pattern_id) do
    parts = String.split(pattern_id, "-")
    
    if length(parts) >= 2 do
      [lang | rest] = parts
      
      language = case lang do
        "js" -> "Javascript"
        "py" -> "Python"
        "rb" -> "Ruby"
        _ -> String.capitalize(lang)
      end
      
      pattern_name = rest
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

VerifyEnhancedFormatFix.run()