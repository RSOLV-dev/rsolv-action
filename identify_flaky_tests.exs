#!/usr/bin/env elixir

# Script to identify flaky tests by running them multiple times
# with different seeds and tracking which tests fail inconsistently

defmodule FlakyTestIdentifier do
  def run(iterations \\ 5) do
    IO.puts("Running tests #{iterations} times to identify flaky tests...")
    
    results = for i <- 1..iterations do
      seed = :rand.uniform(10000)
      IO.puts("\nRun #{i}/#{iterations} with seed #{seed}...")
      
      {output, _exit_code} = System.cmd("mix", [
        "test", 
        "--exclude", "skip",
        "--exclude", "integration",
        "--seed", Integer.to_string(seed),
        "--formatter", "ExUnit.CLIFormatter",
        "--trace"
      ], [
        cd: ".",
        stderr_to_stdout: true
      ])
      
      # Extract failed test names
      failed_tests = extract_failed_tests(output)
      failure_count = extract_failure_count(output)
      
      %{
        seed: seed,
        failures: failure_count,
        failed_tests: failed_tests
      }
    end
    
    analyze_results(results)
  end
  
  defp extract_failed_tests(output) do
    # Match lines like "  1) test some test name (ModuleName)"
    regex = ~r/^\s+\d+\)\s+test\s+(.+)\s+\((.+)\)$/m
    
    Regex.scan(regex, output)
    |> Enum.map(fn [_full, test_name, module_name] ->
      "#{module_name}.#{test_name}"
    end)
  end
  
  defp extract_failure_count(output) do
    # Match "X failures" at the end
    case Regex.run(~r/(\d+)\s+failures/, output) do
      [_, count] -> String.to_integer(count)
      _ -> 0
    end
  end
  
  defp analyze_results(results) do
    IO.puts("\n\n=== FLAKY TEST ANALYSIS ===\n")
    
    # Collect all unique failed tests
    all_failed_tests = results
    |> Enum.flat_map(& &1.failed_tests)
    |> Enum.uniq()
    |> Enum.sort()
    
    # Count how many times each test failed
    test_failure_counts = Enum.reduce(results, %{}, fn result, acc ->
      Enum.reduce(result.failed_tests, acc, fn test, acc2 ->
        Map.update(acc2, test, 1, &(&1 + 1))
      end)
    end)
    
    # Categorize tests
    total_runs = length(results)
    always_failing = Enum.filter(test_failure_counts, fn {_test, count} -> count == total_runs end)
    sometimes_failing = Enum.filter(test_failure_counts, fn {_test, count} -> count > 0 && count < total_runs end)
    
    IO.puts("Total test runs: #{total_runs}")
    IO.puts("Failure counts per run: #{results |> Enum.map(& &1.failures) |> Enum.join(", ")}")
    
    if length(always_failing) > 0 do
      IO.puts("\n## Tests that ALWAYS fail:")
      Enum.each(always_failing, fn {test, count} ->
        IO.puts("  - #{test} (failed #{count}/#{total_runs} times)")
      end)
    end
    
    if length(sometimes_failing) > 0 do
      IO.puts("\n## FLAKY tests (fail sometimes):")
      Enum.each(sometimes_failing, fn {test, count} ->
        percentage = round(count / total_runs * 100)
        IO.puts("  - #{test} (failed #{count}/#{total_runs} times - #{percentage}%)")
      end)
    end
    
    if length(all_failed_tests) == 0 do
      IO.puts("\nNo failures detected across all runs!")
    end
  end
end

# Run the analysis
FlakyTestIdentifier.run(3)