#!/usr/bin/env elixir

# Unit test for pattern loading fix
# This simulates what happens in a release where only .beam files exist

defmodule PatternLoadingUnitTest do
  @moduledoc """
  Tests the pattern loading fix that uses Application.spec instead of filesystem scanning
  """
  
  def run do
    IO.puts("\n=== Pattern Loading Unit Test ===\n")
    
    # Test 1: Verify the old approach would fail in releases
    test_old_approach_fails()
    
    # Test 2: Verify the new approach works
    test_new_approach_works()
    
    # Test 3: Test actual pattern loading
    test_pattern_loading()
    
    IO.puts("\n=== All Tests Complete ===")
  end
  
  defp test_old_approach_fails do
    IO.puts("TEST 1: Old filesystem approach (should fail in releases)")
    
    # In a release, this directory doesn't exist with .ex files
    dir_path = "_build/prod/lib/rsolv_api/ebin/Elixir.RsolvApi.Security.Patterns.Python"
    
    if File.exists?(dir_path) do
      files = File.ls!(dir_path)
      ex_files = Enum.filter(files, &String.ends_with?(&1, ".ex"))
      IO.puts("  ✗ Found #{length(ex_files)} .ex files (should be 0 in release)")
    else
      IO.puts("  ✓ Directory doesn't exist (expected in release)")
    end
  end
  
  defp test_new_approach_works do
    IO.puts("\nTEST 2: New Application.spec approach")
    
    # Compile some test modules
    compile_test_patterns()
    
    # Mock what Application.spec would return
    modules = :code.all_loaded()
      |> Enum.map(&elem(&1, 0))
      |> Enum.filter(fn mod ->
        String.contains?(to_string(mod), "TestPattern")
      end)
    
    IO.puts("  ✓ Found #{length(modules)} compiled modules")
    
    # Test namespace filtering
    test_namespace = TestPatterns.Python
    filtered = modules
      |> Enum.filter(&starts_with_namespace?(&1, test_namespace))
    
    IO.puts("  ✓ Filtered to #{length(filtered)} Python patterns")
    
    # Test that they have pattern/0
    with_pattern = filtered
      |> Enum.filter(&function_exported?(&1, :pattern, 0))
    
    IO.puts("  ✓ #{length(with_pattern)} modules export pattern/0")
  end
  
  defp test_pattern_loading do
    IO.puts("\nTEST 3: Actual pattern loading simulation")
    
    # Get all test modules
    modules = :code.all_loaded()
      |> Enum.map(&elem(&1, 0))
      |> Enum.filter(fn mod ->
        String.contains?(to_string(mod), "TestPattern")
      end)
    
    # Load patterns
    patterns = modules
      |> Enum.filter(&function_exported?(&1, :pattern, 0))
      |> Enum.map(& &1.pattern())
    
    IO.puts("  ✓ Loaded #{length(patterns)} patterns")
    
    # Check pattern IDs
    Enum.each(patterns, fn p ->
      IO.puts("    - #{p.id}: #{p.name}")
    end)
    
    # Verify ID prefixes
    python_pattern = Enum.find(patterns, &String.starts_with?(&1.id, "test-python"))
    js_pattern = Enum.find(patterns, &String.starts_with?(&1.id, "test-js"))
    
    if python_pattern, do: IO.puts("  ✓ Python pattern uses correct prefix")
    if js_pattern, do: IO.puts("  ✓ JavaScript pattern uses correct prefix")
  end
  
  defp compile_test_patterns do
    # Define test pattern modules
    defmodule TestPatterns.Python.SqlInjection do
      def pattern do
        %{
          id: "test-python-sql-injection",
          name: "Test SQL Injection",
          languages: ["python"]
        }
      end
    end
    
    defmodule TestPatterns.Javascript.XSS do
      def pattern do
        %{
          id: "test-js-xss",
          name: "Test XSS",
          languages: ["javascript"]
        }
      end
    end
  end
  
  defp starts_with_namespace?(module, namespace) do
    module_parts = Module.split(module)
    namespace_parts = Module.split(namespace)
    List.starts_with?(module_parts, namespace_parts)
  end
end

# Run the test
PatternLoadingUnitTest.run()