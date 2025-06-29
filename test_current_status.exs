#!/usr/bin/env elixir

IO.puts "=== Current Status Check ===\n"

# 1. Check Elixir version and JSON module
IO.puts "1. Environment Check:"
IO.puts "   Elixir version: #{System.version()}"
IO.puts "   JSON module available: #{Code.ensure_loaded?(JSON)}"

# 2. Check if JSONSerializer works
try do
  Code.compile_file("/home/dylan/dev/rsolv/RSOLV-api/lib/rsolv_api/security/patterns/json_serializer.ex")
  alias RSOLVApi.Security.Patterns.JSONSerializer
  
  test_data = %{pattern: ~r/test/}
  result = JSONSerializer.encode!(test_data)
  IO.puts "\n2. JSONSerializer Check:"
  IO.puts "   ✓ Successfully compiled and can encode regex"
rescue
  e ->
    IO.puts "\n2. JSONSerializer Check:"
    IO.puts "   ✗ Error: #{inspect(e)}"
end

# 3. Check compilation warnings
IO.puts "\n3. Compilation Status:"
{output, _} = System.cmd("mix", ["compile", "--warnings-as-errors"], stderr_to_stdout: true)
warnings = output |> String.split("\n") |> Enum.filter(&String.contains?(&1, "warning:"))
IO.puts "   Total warnings: #{length(warnings)}"

if length(warnings) > 0 do
  IO.puts "   Major warning categories:"
  
  unused_functions = Enum.filter(warnings, &String.contains?(&1, "is unused"))
  IO.puts "   - Unused functions: #{length(unused_functions)}"
  
  json_warnings = Enum.filter(warnings, &String.contains?(&1, "JSON"))
  IO.puts "   - JSON-related: #{length(json_warnings)}"
  
  type_warnings = Enum.filter(warnings, &String.contains?(&1, "incompatible types"))
  IO.puts "   - Type incompatibilities: #{length(type_warnings)}"
end

# 4. Check for Jason usage
IO.puts "\n4. Jason Migration Status:"
{jason_files, _} = System.cmd("grep", ["-r", "Jason\\.", "lib/", "--include=*.ex"], stderr_to_stdout: true)
jason_count = jason_files |> String.split("\n") |> Enum.filter(&(&1 != "")) |> length()
IO.puts "   Files still using Jason: #{jason_count}"

# 5. RFC-032 Phase Status
IO.puts "\n5. RFC-032 Implementation Status:"
IO.puts "   Phase 1.1: ✅ Write failing test for JSON encoding regex"
IO.puts "   Phase 1.2: ✅ Implement prepare_for_json/1"
IO.puts "   Phase 1.3: ✅ Replace Jason with native JSON"
IO.puts "   Phase 1.4: 🔄 Update pattern controller (in progress)"
IO.puts "   Phase 1.5: ⏳ Test enhanced format returns successfully"

IO.puts "\n=== Next Steps ===\n"
IO.puts "1. Complete Phase 1.4: Ensure pattern controller properly uses JSONSerializer"
IO.puts "2. Test enhanced format API endpoint"
IO.puts "3. Move to Phase 2: TypeScript client updates"