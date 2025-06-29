#!/usr/bin/env elixir

# Quick test to verify enhanced format includes AST data

# First, let's test the pattern module directly
alias RsolvApi.Security.Patterns.Javascript.EvalUserInput

IO.puts("\n🔍 Testing Enhanced Pattern Format...\n")

# Get the pattern
pattern = EvalUserInput.pattern()
IO.puts("Pattern ID: #{pattern.id}")

# Check if ast_enhancement exists
if function_exported?(EvalUserInput, :ast_enhancement, 0) do
  IO.puts("✅ Pattern has ast_enhancement/0 function")
  
  enhancement = EvalUserInput.ast_enhancement()
  IO.puts("\n📋 AST Enhancement Data:")
  IO.inspect(enhancement, pretty: true, limit: :infinity)
  
  # Check JSONSerializer
  alias RSOLVApi.Security.Patterns.JSONSerializer
  
  IO.puts("\n🔄 Testing JSON serialization...")
  
  # Prepare enhanced data with regex
  enhanced_data = %{
    pattern: pattern,
    ast_rules: enhancement.ast_rules,
    context_rules: enhancement.context_rules,
    confidence_rules: enhancement.confidence_rules,
    min_confidence: enhancement.min_confidence
  }
  
  try do
    json_encoded = JSONSerializer.encode!(enhanced_data)
    IO.puts("✅ Successfully encoded to JSON (#{byte_size(json_encoded)} bytes)")
    
    # Verify it's valid JSON
    decoded = JSON.decode!(json_encoded)
    IO.puts("✅ Successfully decoded back from JSON")
    
    # Check for serialized regex
    json_str = to_string(json_encoded)
    if String.contains?(json_str, ~s("__type__":"regex")) do
      IO.puts("✅ Contains serialized regex objects")
    else
      IO.puts("⚠️  No serialized regex found")
    end
    
  rescue
    e ->
      IO.puts("❌ JSON encoding failed: #{inspect(e)}")
  end
else
  IO.puts("❌ Pattern does not have ast_enhancement/0")
end