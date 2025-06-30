#!/usr/bin/env elixir

# Test pattern registry in production-like environment

# Set up paths
Mix.start()
Mix.env(:prod)
Code.prepend_path("_build/prod/lib/rsolv_api/ebin")

# Start the application
{:ok, _} = Application.ensure_all_started(:rsolv_api)

alias RsolvApi.Security.PatternRegistry

IO.puts("\n=== Pattern Registry Production Test ===\n")

# Test 1: Python patterns
IO.puts("1. Python Patterns:")
python_patterns = PatternRegistry.get_patterns_for_language("python")
IO.puts("   Count: #{length(python_patterns)}")
if length(python_patterns) > 0 do
  sample = Enum.take(python_patterns, 3)
  Enum.each(sample, fn p ->
    IO.puts("   - #{p.id}: #{p.name}")
  end)
end

# Test 2: JavaScript patterns
IO.puts("\n2. JavaScript Patterns:")
js_patterns = PatternRegistry.get_patterns_for_language("javascript")
IO.puts("   Count: #{length(js_patterns)}")
if length(js_patterns) > 0 do
  # Check for js- prefix
  js_prefixed = Enum.filter(js_patterns, fn p -> String.starts_with?(p.id, "js-") end)
  IO.puts("   With js- prefix: #{length(js_prefixed)}")
  
  sample = Enum.take(js_patterns, 3)
  Enum.each(sample, fn p ->
    IO.puts("   - #{p.id}: #{p.name}")
  end)
end

# Test 3: PHP patterns
IO.puts("\n3. PHP Patterns:")
php_patterns = PatternRegistry.get_patterns_for_language("php")
IO.puts("   Count: #{length(php_patterns)}")
if length(php_patterns) > 0 do
  sample = Enum.take(php_patterns, 3)
  Enum.each(sample, fn p ->
    IO.puts("   - #{p.id}: #{p.name}")
  end)
end

# Test 4: All patterns
IO.puts("\n4. All Patterns Summary:")
all_patterns = PatternRegistry.get_all_patterns()
IO.puts("   Total count: #{length(all_patterns)}")

# Group by language
by_language = all_patterns
  |> Enum.flat_map(fn p -> 
    Enum.map(p.languages || [], fn lang -> {lang, p} end) 
  end)
  |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))

IO.puts("\n   By Language:")
Enum.each(by_language, fn {lang, patterns} ->
  IO.puts("   - #{lang}: #{length(patterns)} patterns")
end)

# Test 5: Common patterns
IO.puts("\n5. Common Patterns:")
common_patterns = all_patterns
  |> Enum.filter(fn p -> 
    String.contains?(p.id, "jwt") || 
    String.contains?(p.id, "weak") ||
    String.contains?(p.id, "hardcoded")
  end)
IO.puts("   Count: #{length(common_patterns)}")
if length(common_patterns) > 0 do
  Enum.each(common_patterns, fn p ->
    IO.puts("   - #{p.id}: #{p.name} (#{inspect(p.languages)})")
  end)
end

# Test 6: Application.spec verification
IO.puts("\n6. Module Loading Verification:")
case Application.spec(:rsolv_api, :modules) do
  modules when is_list(modules) ->
    pattern_modules = modules
      |> Enum.filter(fn mod ->
        mod_str = to_string(mod)
        String.contains?(mod_str, "RsolvApi.Security.Patterns") &&
        !String.ends_with?(mod_str, "PatternBase")
      end)
    
    IO.puts("   Total pattern modules: #{length(pattern_modules)}")
    
    # Count by language
    language_counts = %{
      "Python" => Enum.count(pattern_modules, &String.contains?(to_string(&1), ".Python.")),
      "Javascript" => Enum.count(pattern_modules, &String.contains?(to_string(&1), ".Javascript.")),
      "Php" => Enum.count(pattern_modules, &String.contains?(to_string(&1), ".Php.")),
      "Ruby" => Enum.count(pattern_modules, &String.contains?(to_string(&1), ".Ruby.")),
      "Common" => Enum.count(pattern_modules, &String.contains?(to_string(&1), ".Common."))
    }
    
    IO.puts("\n   Module counts by namespace:")
    Enum.each(language_counts, fn {lang, count} ->
      IO.puts("   - #{lang}: #{count} modules")
    end)
    
  _ ->
    IO.puts("   ERROR: Could not get modules from Application.spec")
end

IO.puts("\n=== Test Complete ===\n")