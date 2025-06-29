#!/usr/bin/env elixir

# Direct test of pattern controller to see what's happening with enhanced format

# Load just the modules we need
Code.require_file("lib/rsolv_api/security/pattern.ex")
Code.require_file("lib/rsolv_api/security/patterns/pattern_base.ex")
Code.require_file("lib/rsolv_api/security/patterns/javascript/eval_user_input.ex")
Code.require_file("lib/rsolv_api/security/patterns/json_serializer.ex")

IO.puts("\n🔍 Direct Pattern Controller Test\n")

# 1. Test the pattern module directly
pattern_module = RsolvApi.Security.Patterns.Javascript.EvalUserInput

IO.puts("1️⃣ Testing Pattern Module Directly:")
pattern = pattern_module.pattern()
IO.puts("   Pattern ID: #{pattern.id}")
IO.puts("   Has pattern/0: ✅")

if function_exported?(pattern_module, :ast_enhancement, 0) do
  IO.puts("   Has ast_enhancement/0: ✅")
  
  enhancement = pattern_module.ast_enhancement()
  IO.puts("\n   Enhancement data:")
  IO.puts("   - AST rules: #{map_size(enhancement.ast_rules) > 0}")
  IO.puts("   - Context rules: #{map_size(enhancement.context_rules) > 0}")  
  IO.puts("   - Confidence rules: #{map_size(enhancement.confidence_rules) > 0}")
  IO.puts("   - Min confidence: #{enhancement.min_confidence}")
else
  IO.puts("   Has ast_enhancement/0: ❌")
end

# 2. Test JSONSerializer
IO.puts("\n2️⃣ Testing JSONSerializer:")
alias RSOLVApi.Security.Patterns.JSONSerializer

test_data = %{
  id: pattern.id,
  regex: pattern.regex,
  ast_rules: %{
    node_type: "CallExpression",
    exclude_paths: [~r/test/, ~r/spec/]
  }
}

try do
  encoded = JSONSerializer.encode!(test_data)
  IO.puts("   JSONSerializer.encode!: ✅")
  IO.puts("   Encoded size: #{byte_size(encoded)} bytes")
  
  # Check for serialized regex
  if String.contains?(encoded, ~s("__type__":"regex")) do
    IO.puts("   Contains serialized regex: ✅")
  else
    IO.puts("   Contains serialized regex: ❌")
  end
rescue
  e ->
    IO.puts("   JSONSerializer.encode!: ❌")
    IO.inspect(e)
end

# 3. Simulate what pattern controller should do
IO.puts("\n3️⃣ Simulating Pattern Controller Flow:")

# This is what format_pattern_without_tier should do for enhanced format
if function_exported?(pattern_module, :ast_enhancement, 0) do
  enhancement = pattern_module.ast_enhancement()
  
  # Build the enhanced response
  enhanced_pattern = %{
    id: pattern.id,
    name: pattern.name,
    description: pattern.description,
    type: to_string(pattern.type),
    severity: to_string(pattern.severity),
    regex_patterns: [pattern.regex],
    languages: pattern.languages,
    cwe_id: pattern.cwe_id,
    owasp_category: pattern.owasp_category,
    recommendation: pattern.recommendation,
    test_cases: pattern.test_cases,
    # Enhanced fields
    ast_rules: enhancement.ast_rules,
    context_rules: enhancement.context_rules,
    confidence_rules: enhancement.confidence_rules,
    min_confidence: enhancement.min_confidence
  }
  
  IO.puts("   Built enhanced pattern: ✅")
  IO.puts("   Has ast_rules: #{Map.has_key?(enhanced_pattern, :ast_rules)}")
  IO.puts("   Has context_rules: #{Map.has_key?(enhanced_pattern, :context_rules)}")
  
  # Try to encode it
  try do
    encoded = JSONSerializer.encode!(enhanced_pattern)
    IO.puts("   JSONSerializer encoding: ✅")
    IO.puts("   Final size: #{byte_size(encoded)} bytes")
  rescue
    e ->
      IO.puts("   JSONSerializer encoding: ❌")
      IO.inspect(e)
  end
end

IO.puts("\n✅ Test complete!")