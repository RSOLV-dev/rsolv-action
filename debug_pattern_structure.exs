#!/usr/bin/env elixir

# TDD GREEN Phase: Debug Pattern Structure in Container
# Run this in the container with: docker-compose exec rsolv-api elixir debug_pattern_structure.exs

IO.puts("🟢 TDD GREEN Phase: Pattern Structure Debug")
IO.puts("=" |> String.duplicate(50))
IO.puts("Elixir version: #{System.version()}")

# First, let's manually inspect what patterns look like
# We'll simulate the pattern loading process

IO.puts("\n1. Checking Pattern Registry module...")
pattern_registry_path = "/app/lib/rsolv_api/security/pattern_registry.ex"
if File.exists?(pattern_registry_path) do
  IO.puts("✅ Pattern Registry found at: #{pattern_registry_path}")
else
  IO.puts("❌ Pattern Registry not found!")
end

IO.puts("\n2. Looking for compiled pattern modules...")
# Check for compiled pattern beam files
beam_pattern = Path.join(["/app", "_build", "dev", "lib", "rsolv_api", "ebin", "*pattern*.beam"])
pattern_beams = Path.wildcard(beam_pattern)
IO.puts("Found #{length(pattern_beams)} pattern beam files")

if length(pattern_beams) > 0 do
  IO.puts("Pattern beam files:")
  Enum.each(pattern_beams, fn beam ->
    IO.puts("  - #{Path.basename(beam)}")
  end)
end

IO.puts("\n3. Attempting to load application and inspect patterns...")
# We need to start the application to access patterns
try do
  # Load the application without starting it
  :ok = Application.load(:rsolv_api)
  
  # Try to access the pattern registry directly
  if Code.ensure_loaded?(RsolvApi.Security.PatternRegistry) do
    IO.puts("✅ PatternRegistry module loaded")
    
    # Check if we can call pattern functions
    if function_exported?(RsolvApi.Security.PatternRegistry, :get_patterns_for_language, 1) do
      IO.puts("✅ get_patterns_for_language/1 function exists")
      
      # Try to get Python patterns
      try do
        patterns = RsolvApi.Security.PatternRegistry.get_patterns_for_language("python")
        IO.puts("\n📋 Python patterns found: #{length(patterns)}")
        
        if length(patterns) > 0 do
          # Inspect the first pattern's structure
          first_pattern = hd(patterns)
          IO.puts("\n🔍 First Python pattern structure:")
          IO.inspect(first_pattern, pretty: true, limit: :infinity)
          
          # Check specific fields
          IO.puts("\n📊 Pattern field analysis:")
          IO.puts("  - Has :id? #{Map.has_key?(first_pattern, :id)}")
          IO.puts("  - Has :ast_rules? #{Map.has_key?(first_pattern, :ast_rules)}")
          IO.puts("  - Has :context_rules? #{Map.has_key?(first_pattern, :context_rules)}")
          IO.puts("  - Has :confidence? #{Map.has_key?(first_pattern, :confidence)}")
          
          if Map.has_key?(first_pattern, :ast_rules) do
            IO.puts("\n🔍 AST rules structure:")
            IO.inspect(first_pattern.ast_rules, pretty: true, limit: :infinity)
          end
        end
      rescue
        error ->
          IO.puts("❌ Error getting patterns: #{inspect(error)}")
      end
    else
      IO.puts("❌ get_patterns_for_language/1 function not found")
    end
  else
    IO.puts("❌ PatternRegistry module not loaded")
  end
rescue
  error ->
    IO.puts("❌ Error loading application: #{inspect(error)}")
end

IO.puts("\n4. Testing pattern matching simulation...")
# Simulate what the pattern matcher should be doing
test_ast_node = %{
  "type" => "BinOp",
  "op" => %{"type" => "Add"},
  "left" => %{
    "type" => "Constant",
    "value" => "SELECT * FROM users WHERE id = "
  },
  "right" => %{
    "type" => "Name",
    "id" => "user_id"
  }
}

expected_pattern = %{
  ast_rules: %{
    node_type: "BinOp",
    op: "Add"
  }
}

IO.puts("\n🧪 Testing operator matching logic:")
IO.puts("AST op: #{inspect(test_ast_node["op"])}")
IO.puts("Pattern op: #{inspect(expected_pattern.ast_rules.op)}")

# Test the matching logic
op_matches = case {test_ast_node["op"], expected_pattern.ast_rules.op} do
  {%{"type" => op_type}, expected_op} when is_binary(expected_op) ->
    op_type == expected_op
  {actual, expected} ->
    actual == expected
end

IO.puts("Operator matches? #{op_matches}")

IO.puts("\n✅ GREEN Phase Next Steps:")
IO.puts("1. If patterns are loaded, check their actual structure")
IO.puts("2. If patterns match expected format, trace through full matching flow")
IO.puts("3. If patterns don't load, investigate pattern compilation")