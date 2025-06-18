#!/usr/bin/env elixir

# Script to analyze all security patterns and create inventory

defmodule PatternAnalyzer do
  @pattern_dir "lib/rsolv_api/security/patterns"
  
  def run do
    IO.puts("Analyzing security patterns in RSOLV-api...\n")
    
    # Get all pattern files
    pattern_files = find_pattern_files()
    
    # Group patterns by language
    initial_patterns = %{
      "javascript" => [],
      "python" => [],
      "ruby" => [],
      "java" => [],
      "elixir" => [],
      "php" => [],
      "rails" => [],
      "django" => [],
      "cve" => [],
      "common" => []
    }
    
    # Process each file
    patterns_by_language = Enum.reduce(pattern_files, initial_patterns, fn file, acc ->
      language = detect_language(file)
      patterns = extract_patterns_from_file(file)
      
      Map.update(acc, language, patterns, &(&1 ++ patterns))
    end)
    
    # Print summary
    print_summary(patterns_by_language)
    
    # Analyze tier distribution
    analyze_tier_distribution(patterns_by_language)
    
    # Analyze pattern types
    analyze_pattern_types(patterns_by_language)
    
    # Analyze severity distribution
    analyze_severity_distribution(patterns_by_language)
  end
  
  defp find_pattern_files do
    Path.wildcard("#{@pattern_dir}/**/*.ex")
    |> Enum.reject(&String.contains?(&1, "_test.ex"))
    |> Enum.reject(&String.ends_with?(&1, "/pattern_base.ex"))
  end
  
  defp detect_language(file_path) do
    cond do
      String.contains?(file_path, "/javascript/") -> "javascript"
      String.contains?(file_path, "/python/") -> "python"
      String.contains?(file_path, "/ruby/") -> "ruby"
      String.contains?(file_path, "/java/") -> "java"
      String.contains?(file_path, "/elixir/") -> "elixir"
      String.contains?(file_path, "/php/") -> "php"
      String.contains?(file_path, "/rails/") -> "rails"
      String.contains?(file_path, "/django/") -> "django"
      String.contains?(file_path, "/cve/") -> "cve"
      String.contains?(file_path, "/common/") -> "common"
      String.ends_with?(file_path, "/javascript.ex") -> "javascript"
      String.ends_with?(file_path, "/python.ex") -> "python"
      String.ends_with?(file_path, "/ruby.ex") -> "ruby"
      String.ends_with?(file_path, "/java.ex") -> "java"
      String.ends_with?(file_path, "/elixir.ex") -> "elixir"
      String.ends_with?(file_path, "/php.ex") -> "php"
      String.ends_with?(file_path, "/rails.ex") -> "rails"
      String.ends_with?(file_path, "/django.ex") -> "django"
      String.ends_with?(file_path, "/cve.ex") -> "cve"
      true -> "unknown"
    end
  end
  
  defp extract_patterns_from_file(file_path) do
    content = File.read!(file_path)
    
    # Look for pattern definitions in individual files
    cond do
      content =~ ~r/def pattern do/ ->
        pattern_info = extract_pattern_info(content)
        if pattern_info, do: [pattern_info], else: []
        
      # Look for aggregate pattern files (like javascript.ex)
      content =~ ~r/def all do/ ->
        # Extract individual pattern info from function definitions
        extract_all_patterns_info(content)
        
      true ->
        []
    end
  end
  
  defp extract_pattern_info(content) do
    id = extract_field(content, ~r/id:\s*"([^"]+)"/)
    type = extract_field(content, ~r/type:\s*:(\w+)/)
    severity = extract_field(content, ~r/severity:\s*:(\w+)/)
    tier = extract_field(content, ~r/default_tier:\s*:(\w+)/) || "public"
    name = extract_field(content, ~r/name:\s*"([^"]+)"/)
    
    if id do
      %{
        id: id,
        type: type,
        severity: severity,
        tier: tier,
        name: name
      }
    else
      nil
    end
  end
  
  defp extract_field(content, regex) do
    case Regex.run(regex, content) do
      [_, value] -> value
      _ -> nil
    end
  end
  
  defp extract_all_section(content) do
    case Regex.run(~r/def all do\s*(.*?)\s*end/s, content) do
      [_, section] -> section
      _ -> ""
    end
  end
  
  defp count_pattern_functions(all_section) do
    # Count function calls that end with ()
    Regex.scan(~r/\w+\(\)/, all_section)
    |> length()
  end
  
  defp extract_all_patterns_info(content) do
    # Extract info from each pattern function definition
    function_names = Regex.scan(~r/def\s+(\w+)\s*do/, content)
    |> Enum.map(fn [_, name] -> name end)
    |> Enum.reject(&(&1 in ["all", "pattern", "vulnerability_metadata", "ast_enhancement"]))
    
    # For aggregate files, we'll just count them
    Enum.map(function_names, fn name ->
      %{
        id: name,
        type: guess_type_from_name(name),
        severity: "unknown",
        tier: "public",
        name: humanize_name(name)
      }
    end)
  end
  
  defp guess_type_from_name(name) do
    cond do
      String.contains?(name, "sql_injection") -> "sql_injection"
      String.contains?(name, "xss") -> "xss"
      String.contains?(name, "command_injection") -> "command_injection"
      String.contains?(name, "path_traversal") -> "path_traversal"
      String.contains?(name, "csrf") -> "csrf"
      String.contains?(name, "xxe") -> "xxe"
      String.contains?(name, "ldap") -> "ldap_injection"
      String.contains?(name, "xpath") -> "xpath_injection"
      String.contains?(name, "ssrf") -> "ssrf"
      String.contains?(name, "crypto") -> "weak_crypto"
      String.contains?(name, "hash") -> "weak_crypto"
      String.contains?(name, "hardcoded") -> "hardcoded_secret"
      String.contains?(name, "eval") -> "code_injection"
      String.contains?(name, "deserializ") -> "insecure_deserialization"
      String.contains?(name, "random") -> "weak_random"
      String.contains?(name, "auth") -> "authentication"
      true -> "other"
    end
  end
  
  defp humanize_name(name) do
    name
    |> String.split("_")
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end
  
  defp print_summary(patterns_by_language) do
    IO.puts("## Pattern Inventory Summary\n")
    
    total = Enum.reduce(patterns_by_language, 0, fn {_, patterns}, acc ->
      acc + length(patterns)
    end)
    
    IO.puts("Total patterns: #{total}\n")
    
    IO.puts("### Patterns by Language/Framework:")
    Enum.each(patterns_by_language, fn {language, patterns} ->
      if length(patterns) > 0 do
        IO.puts("- #{String.capitalize(language)}: #{length(patterns)} patterns")
      end
    end)
    
    IO.puts("")
  end
  
  defp analyze_tier_distribution(patterns_by_language) do
    IO.puts("### Tier Distribution:\n")
    
    all_patterns = patterns_by_language
    |> Map.values()
    |> List.flatten()
    
    tier_counts = Enum.reduce(all_patterns, %{}, fn pattern, acc ->
      tier = pattern.tier || "public"
      Map.update(acc, tier, 1, &(&1 + 1))
    end)
    
    Enum.each(tier_counts, fn {tier, count} ->
      percentage = Float.round(count / length(all_patterns) * 100, 1)
      IO.puts("- #{String.capitalize(tier)}: #{count} patterns (#{percentage}%)")
    end)
    
    IO.puts("")
  end
  
  defp analyze_pattern_types(patterns_by_language) do
    IO.puts("### Pattern Types Distribution:\n")
    
    all_patterns = patterns_by_language
    |> Map.values()
    |> List.flatten()
    
    type_counts = Enum.reduce(all_patterns, %{}, fn pattern, acc ->
      type = pattern.type || "unknown"
      Map.update(acc, type, 1, &(&1 + 1))
    end)
    
    type_counts
    |> Enum.sort_by(fn {_, count} -> -count end)
    |> Enum.each(fn {type, count} ->
      IO.puts("- #{type}: #{count} patterns")
    end)
    
    IO.puts("")
  end
  
  defp analyze_severity_distribution(patterns_by_language) do
    IO.puts("### Severity Distribution:\n")
    
    all_patterns = patterns_by_language
    |> Map.values()
    |> List.flatten()
    
    severity_counts = Enum.reduce(all_patterns, %{}, fn pattern, acc ->
      severity = pattern.severity || "unknown"
      Map.update(acc, severity, 1, &(&1 + 1))
    end)
    
    # Order by severity level
    severity_order = ["critical", "high", "medium", "low", "unknown"]
    
    Enum.each(severity_order, fn severity ->
      if count = severity_counts[severity] do
        percentage = Float.round(count / length(all_patterns) * 100, 1)
        IO.puts("- #{String.capitalize(severity)}: #{count} patterns (#{percentage}%)")
      end
    end)
    
    IO.puts("")
  end
end

# Run the analyzer
PatternAnalyzer.run()