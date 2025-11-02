#!/usr/bin/env elixir

# Merge .coverdata files from partitioned test runs and generate coverage report
# This script merges coverage WITHOUT re-running tests

IO.puts("🔍 Searching for coverage data files...")
coverdata_files = Path.wildcard("cover/*.coverdata")

if Enum.empty?(coverdata_files) do
  IO.puts("❌ No coverage data files found!")
  System.halt(1)
end

IO.puts("✅ Found #{length(coverdata_files)} coverage data files:")
Enum.each(coverdata_files, &IO.puts("   - #{&1}"))

IO.puts("\n📊 Merging coverage data...")

# Import all .coverdata files
Enum.each(coverdata_files, fn file ->
  case :cover.import(String.to_charlist(file)) do
    :ok -> IO.puts("   ✓ Imported #{file}")
    {:error, reason} ->
      IO.puts("   ✗ Failed to import #{file}: #{inspect(reason)}")
      System.halt(1)
  end
end)

IO.puts("\n📈 Analyzing coverage...")

# Get all imported modules (use imported/0 not modules/0)
# :cover.modules() only returns modules compiled with cover enabled
# :cover.imported() returns all modules that have coverage data from imports
modules = :cover.imported()
IO.puts("Analyzing #{length(modules)} modules...")

# Calculate coverage
{covered, total} =
  Enum.reduce(modules, {0, 0}, fn mod, {cov_acc, tot_acc} ->
    result = :cover.analyze(mod, :coverage, :line)

    case result do
      {:ok, lines} ->
        IO.puts("   ✓ Module #{mod}: :ok format with #{length(lines)} lines")
        {cov, tot} =
          Enum.reduce(lines, {0, 0}, fn
            {_line, 0}, {c, t} -> {c, t + 1}  # Not covered
            {_line, _n}, {c, t} -> {c + 1, t + 1}  # Covered
          end)
        {cov_acc + cov, tot_acc + tot}

      # Handle imported modules that aren't recompiled with cover
      {:result, lines, _warnings} when is_list(lines) ->
        IO.puts("   ✓ Module #{mod}: :result format with #{length(lines)} lines")
        {cov, tot} =
          Enum.reduce(lines, {0, 0}, fn
            {{_mod, _line}, 0}, {c, t} -> {c, t + 1}  # Not covered
            {{_mod, _line}, _n}, {c, t} -> {c + 1, t + 1}  # Covered
          end)
        {cov_acc + cov, tot_acc + tot}

      {:error, reason} ->
        IO.puts("   ✗ Module #{mod}: error - #{inspect(reason)}")
        {cov_acc, tot_acc}

      # Catch any other format
      other ->
        IO.puts("   ⚠️  Module #{mod}: unexpected format")
        IO.puts("      First 3 items: #{inspect(Enum.take(other, 3))}")
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

# Generate simple JSON report for Coveralls
# The coveralls action expects an LCOV-format file or excoveralls.json
# We'll create a minimal JSON that just exports the merged .coverdata
IO.puts("\n📝 Exporting merged coverage data...")

# Export merged coverage to a single .coverdata file
export_file = 'cover/merged.coverdata'
case :cover.export(export_file) do
  :ok ->
    IO.puts("✅ Merged coverage exported to #{export_file}")
  {:error, reason} ->
    IO.puts("⚠️  Failed to export coverage: #{inspect(reason)}")
end

IO.puts("\n✨ Coverage merge complete!")
IO.puts("\n💡 Note: Coveralls upload step should use cover/merged.coverdata")
