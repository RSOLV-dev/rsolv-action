#!/usr/bin/env elixir

# Simple smoke test - just test parsing for all 5 languages

{:ok, _} = Application.ensure_all_started(:rsolv_api)

alias RsolvApi.AST.{SessionManager, ParserRegistry}

IO.puts "🔥 Starting Simple Parser Smoke Test...\n"

# Create a test session
{:ok, session} = SessionManager.create_session("smoke-test-customer")
session_id = session.id

# Test code samples
test_codes = %{
  "javascript" => "function test() { return 'hello'; }",
  "python" => "def test():\n    return 'hello'",
  "ruby" => "def test\n  'hello'\nend",
  "php" => "<?php\nfunction test() { return 'hello'; }\n?>",
  "elixir" => "def test, do: \"hello\""
}

results = Enum.map(test_codes, fn {language, code} ->
  IO.puts "📝 Testing #{language}..."
  
  case ParserRegistry.parse_code(session_id, "smoke-test-customer", language, code) do
    {:ok, %{ast: ast}} ->
      IO.puts "  ✅ Parsing successful"
      {:ok, language}
      
    {:error, reason} ->
      IO.puts "  ❌ Parsing failed: #{inspect(reason)}"
      {:error, language, reason}
  end
end)

# Cleanup not needed - sessions auto-expire

# Summary
IO.puts "\n📊 SUMMARY"
IO.puts "=========="

successful = Enum.count(results, fn {status, _} -> status == :ok end)
failed = Enum.count(results, fn {status, _} -> status == :error end)

IO.puts "✅ Successful: #{successful}/5 languages"
IO.puts "❌ Failed: #{failed}/5 languages"

if successful == 5 do
  IO.puts "\n🎉 All parsers working!"
else
  IO.puts "\n⚠️  Some parsers need attention:"
  Enum.each(results, fn 
    {:error, lang, _reason} -> IO.puts "  - #{lang}"
    _ -> :ok
  end)
end