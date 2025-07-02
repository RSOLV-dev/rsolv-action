# Script to find slow tests by parsing test output
defmodule SlowTestFinder do
  def parse_test_output(file_path) do
    file_path
    |> File.read\!()
    |> String.split("\n")
    |> Enum.filter(&String.contains?(&1, "ms)"))
    |> Enum.map(&parse_test_line/1)
    |> Enum.filter(& &1)
    |> Enum.sort_by(& &1.time, :desc)
    |> Enum.take(50)
  end
  
  defp parse_test_line(line) do
    case Regex.run(~r/\* (.+) \((\d+(?:\.\d+)?)(ms|s)\)/, line) do
      [_, test_name, time, unit] ->
        time_ms = case unit do
          "s" -> String.to_float(time) * 1000
          "ms" -> String.to_float(time)
        end
        %{test: test_name, time: time_ms, line: line}
      _ ->
        nil
    end
  end
end

# Run a subset of tests with trace to capture timing
IO.puts("Running tests to capture timing information...")
System.cmd("mix", ["test", "--trace", "test/rsolv_api/ast", "test/rsolv_api/security"], 
  into: File.stream\!("test_timing.log"))

# Parse and display results
IO.puts("\nTop 50 Slowest Tests:")
IO.puts("=" |> String.duplicate(80))

SlowTestFinder.parse_test_output("test_timing.log")
|> Enum.each(fn %{test: test, time: time} ->
  IO.puts("#{Float.round(time, 1)}ms - #{test}")
end)
