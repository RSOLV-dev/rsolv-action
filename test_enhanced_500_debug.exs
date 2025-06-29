#!/usr/bin/env elixir

# Test script to debug enhanced format 500 error

Mix.start()
Mix.shell(Mix.Shell.Process)

# Start the application
Application.ensure_all_started(:hackney)
Application.ensure_all_started(:httpoison)

IO.puts("Testing Pattern API Enhanced Format...\n")

# Test standard format first
IO.puts("1. Testing standard format (should work):")
case HTTPoison.get("http://localhost:4000/api/v1/patterns?language=javascript&format=standard") do
  {:ok, %{status_code: 200, body: body}} ->
    data = JSON.decode!(body)
    IO.puts("✅ Success! Got #{data["metadata"]["count"]} patterns")
  {:ok, %{status_code: status}} ->
    IO.puts("❌ Failed with status: #{status}")
  {:error, reason} ->
    IO.puts("❌ Connection error: #{inspect(reason)}")
end

IO.puts("\n2. Testing enhanced format (expecting 500):")
case HTTPoison.get("http://localhost:4000/api/v1/patterns?language=javascript&format=enhanced") do
  {:ok, %{status_code: 500, body: body}} ->
    IO.puts("❌ Got 500 error as expected")
    IO.puts("Error body: #{body}")
  {:ok, %{status_code: 200}} ->
    IO.puts("✅ Success! Enhanced format is working")
  {:ok, %{status_code: status, body: body}} ->
    IO.puts("❌ Failed with status: #{status}")
    IO.puts("Body: #{body}")
  {:error, reason} ->
    IO.puts("❌ Connection error: #{inspect(reason)}")
end

# Let's also test direct pattern enhancement
IO.puts("\n3. Testing direct ASTPattern.enhance:")
alias RsolvApi.Security.{Pattern, ASTPattern, DemoPatterns}

demo_patterns = DemoPatterns.get_demo_patterns("javascript")
IO.puts("Got #{length(demo_patterns)} demo patterns")

first_pattern = List.first(demo_patterns)
IO.puts("\nTesting enhancement of: #{first_pattern.id}")

try do
  enhanced = ASTPattern.enhance(first_pattern)
  IO.puts("✅ Enhancement successful!")
  IO.puts("Enhanced pattern type: #{inspect(enhanced.__struct__)}")
  IO.puts("Has AST rules: #{not is_nil(enhanced.ast_rules)}")
rescue
  e ->
    IO.puts("❌ Enhancement failed: #{inspect(e)}")
    IO.puts("Stacktrace:")
    IO.puts(Exception.format_stacktrace())
end