# Debug pattern counting
alias RsolvApi.Security.PatternRegistry

IO.puts("=== Pattern Count Debug ===")

# Get all pattern modules
all_modules = Application.spec(:rsolv_api, :modules) || []
pattern_modules = Enum.filter(all_modules, fn module ->
  module_str = to_string(module)
  String.contains?(module_str, "Patterns") and 
  String.contains?(module_str, "Pattern") and
  not String.contains?(module_str, "Enhanced") and
  not String.contains?(module_str, "Base") and
  not String.contains?(module_str, "Serializer")
end)

IO.puts("\nTotal pattern modules: #{length(pattern_modules)}")

# Count patterns by language
languages = ["javascript", "python", "ruby", "php", "java", "elixir"]
total_patterns = 0

for language <- languages do
  patterns = PatternRegistry.get_patterns_for_language(language)
  count = length(patterns)
  total_patterns = total_patterns + count
  IO.puts("#{language}: #{count} patterns")
end

IO.puts("\nTotal from all languages: #{total_patterns}")

# Check for duplicates across languages
all_pattern_ids = languages
  |> Enum.flat_map(&PatternRegistry.get_patterns_for_language/1)
  |> Enum.map(& &1.id)

unique_ids = all_pattern_ids |> Enum.uniq() |> length()
total_ids = length(all_pattern_ids)

IO.puts("\nDuplicate check:")
IO.puts("Total pattern instances: #{total_ids}")
IO.puts("Unique pattern IDs: #{unique_ids}")
IO.puts("Duplicates: #{total_ids - unique_ids}")

# Check if common patterns are being included multiple times
common_patterns = PatternRegistry.get_patterns_for_language("common")
IO.puts("\nCommon patterns: #{length(common_patterns)}")

# Count actual unique patterns
if unique_ids == total_ids do
  IO.puts("\n✅ No duplicates found")
else
  IO.puts("\n⚠️  Patterns are being counted multiple times!")
  
  # Find which patterns are duplicated
  id_counts = all_pattern_ids
    |> Enum.frequencies()
    |> Enum.filter(fn {_id, count} -> count > 1 end)
    |> Enum.sort_by(fn {_id, count} -> -count end)
    |> Enum.take(5)
  
  IO.puts("\nTop duplicated patterns:")
  for {id, count} <- id_counts do
    IO.puts("  #{id}: appears #{count} times")
  end
end