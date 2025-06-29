#!/usr/bin/env elixir

# Simplified test to find the exact issue

# First let's test the API directly with curl
IO.puts("Testing API endpoints...\n")

# Standard format
IO.puts("1. Standard format:")
{output, _} = System.cmd("curl", ["-s", "http://localhost:4000/api/v1/patterns?language=javascript&format=standard"])
case JSON.decode(output) do
  {:ok, data} ->
    IO.puts("✅ Success! Got #{data["metadata"]["count"]} patterns")
  {:error, _} ->
    IO.puts("❌ Failed to parse response")
    IO.puts("Response: #{String.slice(output, 0, 200)}")
end

# Enhanced format
IO.puts("\n2. Enhanced format:")
{output, _} = System.cmd("curl", ["-s", "http://localhost:4000/api/v1/patterns?language=javascript&format=enhanced"])
case JSON.decode(output) do
  {:ok, data} ->
    if data["error"] do
      IO.puts("❌ Got error: #{data["error"]}")
      IO.puts("Message: #{data["message"]}")
    else
      IO.puts("✅ Success! Got #{data["metadata"]["count"]} patterns")
    end
  {:error, _} ->
    IO.puts("❌ Failed to parse response")
    IO.puts("Response: #{String.slice(output, 0, 200)}")
end

# Let's check the logs
IO.puts("\n3. Checking server output...")
IO.puts("Run this in another terminal to see logs:")
IO.puts("tail -f log/*.log | grep -A5 -B5 'Pattern API'")
IO.puts("\nOr check the terminal where the server is running for error output")