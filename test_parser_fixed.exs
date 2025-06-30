#!/usr/bin/env elixir

# Test parser with correct format
# Run with: docker-compose exec rsolv-api elixir test_parser_fixed.exs

IO.puts("🔍 Testing Parser with Correct Format")
IO.puts("=" |> String.duplicate(60))

# Test SQL injection pattern
test_sql = JSON.encode!(%{
  "id" => "test-sql",
  "command" => ~s(query = "SELECT * FROM users WHERE id = " + user_id),
  "options" => %{"include_security_patterns" => true}
})

IO.puts("\nSQL injection test:")
IO.puts("Sending: #{test_sql}")

{output, code} = System.shell("echo '#{test_sql}' | python3 /app/priv/parsers/python/parser.py")

if code == 0 do
  case JSON.decode(output) do
    {:ok, result} ->
      IO.puts("\n✅ Parser Success!")
      IO.puts("Status: #{result["status"]}")
      
      # Check AST
      ast = result["ast"]
      if ast do
        IO.puts("\nAST Root: #{ast["type"]}")
        
        # Look for Module body
        body = ast["body"] || []
        IO.puts("Body statements: #{length(body)}")
        
        if length(body) > 0 do
          stmt = hd(body)
          IO.puts("\nFirst statement type: #{stmt["type"]}")
          
          if stmt["type"] == "Assign" && stmt["value"] do
            value = stmt["value"]
            IO.puts("Assignment value type: #{value["type"]}")
            
            if value["type"] == "BinOp" do
              IO.puts("\n🎯 Found BinOp!")
              IO.puts("  Op: #{inspect(value["op"])}")
              IO.puts("  Left type: #{value["left"]["type"]}")
              if value["left"]["value"] do
                IO.puts("  Left value: #{inspect(value["left"]["value"])}")
              end
              IO.puts("  Right type: #{value["right"]["type"]}")
              if value["right"]["id"] do
                IO.puts("  Right id: #{value["right"]["id"]}")
              end
              
              # This is what the pattern matcher should see
              IO.puts("\n🔍 Pattern matching check:")
              is_add = value["op"]["type"] == "Add"
              has_sql = value["left"]["value"] && String.contains?(String.downcase(value["left"]["value"]), "select")
              IO.puts("  Is Add? #{is_add}")
              IO.puts("  Has SQL? #{has_sql}")
              IO.puts("  Should match pattern? #{is_add && has_sql}")
            end
          end
        end
      end
      
      # Check security patterns
      patterns = result["security_patterns"] || []
      IO.puts("\nSecurity patterns found: #{length(patterns)}")
      if length(patterns) > 0 do
        IO.inspect(patterns, pretty: true)
      end
      
    {:error, err} -> 
      IO.puts("❌ JSON decode error: #{inspect(err)}")
      IO.puts("Raw output: #{output}")
  end
else
  IO.puts("❌ Parser error (code #{code}): #{output}")
end

IO.puts("\n💡 Key findings:")
IO.puts("1. Parser expects 'command' field, not 'source'")
IO.puts("2. BinOp is nested inside Module -> Assign -> value")
IO.puts("3. The AST structure is correct for pattern matching")