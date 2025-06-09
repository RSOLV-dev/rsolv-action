#!/usr/bin/env elixir

# Test script to verify pattern modules compile and function correctly
# Run with: elixir test_patterns.exs

defmodule PatternTester do
  def test_module(module_name, expected_count) do
    try do
      module = Module.concat([RsolvApi, Security, Patterns, module_name])
      patterns = apply(module, :all, [])
      
      IO.puts("\n✅ #{module_name} module:")
      IO.puts("   - Loaded successfully")
      IO.puts("   - Pattern count: #{length(patterns)}")
      IO.puts("   - Expected: #{expected_count}")
      
      if length(patterns) == expected_count do
        IO.puts("   - ✓ Count matches!")
      else
        IO.puts("   - ✗ Count mismatch!")
      end
      
      # Test first pattern
      if first = List.first(patterns) do
        IO.puts("   - First pattern: #{first.id}")
        IO.puts("   - Type: #{first.type}")
        IO.puts("   - Severity: #{first.severity}")
      end
      
      {:ok, length(patterns)}
    rescue
      e ->
        IO.puts("\n❌ #{module_name} module: Failed to load")
        IO.puts("   Error: #{inspect(e)}")
        {:error, e}
    end
  end
  
  def run do
    IO.puts("Testing RSOLV API Security Pattern Modules...")
    IO.puts("=" |> String.duplicate(50))
    
    modules = [
      {:Javascript, 27},
      {:Python, 12},
      {:Ruby, 20},
      {:Java, 17},
      {:Elixir, 28},
      {:Php, 25},
      {:Cve, 4}
    ]
    
    results = Enum.map(modules, fn {mod, count} -> 
      {mod, test_module(mod, count)}
    end)
    
    IO.puts("\n" <> ("=" |> String.duplicate(50)))
    IO.puts("Summary:")
    
    successful = Enum.count(results, fn {_, result} -> 
      match?({:ok, _}, result)
    end)
    
    total_patterns = results
    |> Enum.filter(fn {_, result} -> match?({:ok, _}, result) end)
    |> Enum.map(fn {_, {:ok, count}} -> count end)
    |> Enum.sum()
    
    IO.puts("Modules loaded: #{successful}/#{length(modules)}")
    IO.puts("Total patterns: #{total_patterns}")
    
    if successful == length(modules) do
      IO.puts("\n🎉 All modules loaded successfully!")
    else
      IO.puts("\n⚠️  Some modules failed to load")
    end
  end
end

# Load the application without starting it
Code.require_file("lib/rsolv_api/security/pattern.ex")
Code.require_file("lib/rsolv_api/security/patterns/javascript.ex")
Code.require_file("lib/rsolv_api/security/patterns/python.ex")
Code.require_file("lib/rsolv_api/security/patterns/java.ex")
Code.require_file("lib/rsolv_api/security/patterns/elixir.ex")
Code.require_file("lib/rsolv_api/security/patterns/php.ex")
Code.require_file("lib/rsolv_api/security/patterns/cve.ex")

# Try to load Ruby module if it compiles
try do
  Code.require_file("lib/rsolv_api/security/patterns/ruby.ex")
rescue
  e -> IO.puts("Note: Ruby module has compilation issues: #{inspect(e)}")
end

PatternTester.run()