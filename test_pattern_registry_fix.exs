#!/usr/bin/env elixir

# Test script to verify pattern registry fix with TDD approach

Mix.install([
  {:rsolv_api, path: ".", env: :test}
])

defmodule PatternRegistryFixTest do
  use ExUnit.Case
  alias RsolvApi.Security.PatternRegistry
  
  describe "pattern loading with Application.spec" do
    test "loads Python patterns" do
      patterns = PatternRegistry.get_patterns_for_language("python")
      pattern_ids = Enum.map(patterns, & &1.id)
      
      IO.puts("Python patterns loaded: #{length(patterns)}")
      IO.puts("Python pattern IDs: #{inspect(pattern_ids)}")
      
      assert length(patterns) > 0, "Should load Python patterns"
      assert "python-sql-injection-concat" in pattern_ids
    end
    
    test "loads JavaScript patterns with correct prefix" do
      patterns = PatternRegistry.get_patterns_for_language("javascript")
      pattern_ids = Enum.map(patterns, & &1.id)
      
      IO.puts("JavaScript patterns loaded: #{length(patterns)}")
      IO.puts("JavaScript pattern IDs: #{inspect(Enum.take(pattern_ids, 5))}")
      
      assert length(patterns) > 0, "Should load JavaScript patterns"
      # JavaScript uses "js-" prefix, not "javascript-"
      assert Enum.any?(pattern_ids, &String.starts_with?(&1, "js-"))
    end
    
    test "loads PHP patterns" do
      patterns = PatternRegistry.get_patterns_for_language("php")
      pattern_ids = Enum.map(patterns, & &1.id)
      
      IO.puts("PHP patterns loaded: #{length(patterns)}")
      IO.puts("PHP pattern IDs: #{inspect(Enum.take(pattern_ids, 5))}")
      
      assert length(patterns) > 0, "Should load PHP patterns"
      assert Enum.any?(pattern_ids, &String.starts_with?(&1, "php-"))
    end
    
    test "loads common patterns" do
      all_patterns = PatternRegistry.get_all_patterns()
      
      # Filter for patterns that might be common
      common_patterns = all_patterns 
        |> Enum.filter(fn p -> 
          String.contains?(p.id, "jwt") || 
          String.contains?(p.id, "hardcoded") ||
          String.contains?(p.id, "secret") ||
          String.contains?(p.id, "weak")
        end)
      
      IO.puts("Common-like patterns found: #{length(common_patterns)}")
      IO.puts("Common pattern IDs: #{inspect(Enum.map(common_patterns, & &1.id) |> Enum.take(10))}")
      
      assert length(common_patterns) > 0, "Should include common patterns"
    end
    
    test "debug: list all available modules" do
      case Application.spec(:rsolv_api, :modules) do
        modules when is_list(modules) ->
          pattern_modules = modules
            |> Enum.filter(&String.contains?(to_string(&1), "Patterns"))
            |> Enum.filter(&String.contains?(to_string(&1), "Php"))
            |> Enum.take(5)
          
          IO.puts("Sample PHP pattern modules: #{inspect(pattern_modules)}")
          
          # Check if they export pattern/0
          pattern_modules
          |> Enum.each(fn mod ->
            has_pattern = function_exported?(mod, :pattern, 0)
            IO.puts("#{mod} exports pattern/0: #{has_pattern}")
          end)
        _ ->
          IO.puts("Could not get modules from application spec")
      end
    end
    
    test "loads patterns from all major languages" do
      languages = ["python", "javascript", "ruby", "php", "java", "elixir"]
      
      results = Enum.map(languages, fn lang ->
        patterns = PatternRegistry.get_patterns_for_language(lang)
        {lang, length(patterns)}
      end)
      
      IO.puts("Pattern counts by language:")
      Enum.each(results, fn {lang, count} ->
        IO.puts("  #{lang}: #{count} patterns")
      end)
      
      # Each language should have at least some patterns
      Enum.each(results, fn {lang, count} ->
        assert count > 0, "Should have patterns for #{lang}"
      end)
    end
  end
end

# Run the tests
ExUnit.start()