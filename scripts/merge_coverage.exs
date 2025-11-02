#!/usr/bin/env elixir

# Merge .coverdata files from partitioned test runs WITHOUT re-running tests

IO.puts("🔍 Searching for coverage data files...")
coverdata_files = Path.wildcard("cover/*.coverdata")

if Enum.empty?(coverdata_files) do
  IO.puts("❌ No coverage data files found!")
  System.halt(1)
end

IO.puts("✅ Found #{length(coverdata_files)} coverage data files:")
Enum.each(coverdata_files, &IO.puts("   - #{&1}"))

IO.puts("\n📊 Merging coverage data...")

# Strategy: Import all .coverdata files, then compile_beam the modules
# This allows :cover.analyze to work without re-running tests

# First, import all coverage data
Enum.each(coverdata_files, fn file ->
  case :cover.import(String.to_charlist(file)) do
    :ok -> IO.puts("   ✓ Imported #{file}")
    {:error, reason} ->
      IO.puts("   ✗ Failed to import #{file}: #{inspect(reason)}")
      System.halt(1)
  end
end)

IO.puts("\n📦 Compiling application modules for coverage analysis...")

# Get all beam files from the build
beam_files = Path.wildcard("_build/test/lib/rsolv/ebin/*.beam")
IO.puts("Found #{length(beam_files)} beam files")

# Compile each beam file with cover
# This loads the modules so :cover.analyze can work
compiled_modules = Enum.reduce(beam_files, [], fn beam_file, acc ->
  module = beam_file
  |> Path.basename(".beam")
  |> String.to_atom()

  # Only compile modules that have imported coverage data
  case :cover.compile_beam(module) do
    {:ok, ^module} ->
      [module | acc]
    {:error, :non_existing} ->
      # Module doesn't have coverage data, skip
      acc
    {:error, reason} ->
      IO.puts("   ⚠️  Failed to compile #{module}: #{inspect(reason)}")
      acc
  end
end)

IO.puts("✅ Compiled #{length(compiled_modules)} modules with coverage")

IO.puts("\n📈 Analyzing coverage...")

# Now analyze the compiled modules
{covered, total} =
  Enum.reduce(compiled_modules, {0, 0}, fn mod, {cov_acc, tot_acc} ->
    case :cover.analyze(mod, :coverage, :line) do
      {:ok, lines} ->
        {cov, tot} =
          Enum.reduce(lines, {0, 0}, fn
            {_line, 0}, {c, t} -> {c, t + 1}  # Not covered
            {_line, _n}, {c, t} -> {c + 1, t + 1}  # Covered
          end)
        {cov_acc + cov, tot_acc + tot}

      {:error, _reason} ->
        {cov_acc, tot_acc}
    end
  end)

coverage_percent = if total > 0, do: Float.round(covered / total * 100, 1), else: 0.0

IO.puts("\n📊 Coverage Results:")
IO.puts("   Covered lines: #{covered}")
IO.puts("   Total lines: #{total}")
IO.puts("   [TOTAL]  #{coverage_percent}%")

# Write coverage percentage to file for GitHub Actions
File.write!("coverage_percent.txt", "#{coverage_percent}")
IO.puts("\n✅ Coverage percentage written to coverage_percent.txt")

IO.puts("\n✨ Coverage merge complete!")
