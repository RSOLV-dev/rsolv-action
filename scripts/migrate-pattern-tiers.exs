#!/usr/bin/env elixir
# Pattern Tier Migration Script
# Run with: cd RSOLV-api && mix run scripts/migrate-pattern-tiers.exs

defmodule PatternTierMigration do
  @moduledoc """
  Migrates patterns from current tier structure to simplified 3-tier model:
  - public (Free/Demo): ~60 basic patterns
  - ai (Professional): ~250 common vulnerability patterns  
  - enterprise: ~140 advanced/CVE patterns
  """
  
  # Patterns that should remain public (demo tier)
  @public_patterns [
    # Basic XSS patterns for demos
    "js-xss-innerhtml",
    "js-xss-document-write",
    "js-xss-jquery-html",
    "py-xss-template",
    "py-xss-format-string",
    "rb-xss-erb-raw",
    "rb-xss-haml-raw",
    "php-xss-echo",
    "php-xss-print",
    "ex-xss-raw",
    "ex-xss-safe-tuple",
    "java-xss-jsp-expression",
    
    # Basic educational patterns
    "js-weak-crypto-md5",
    "py-weak-crypto-md5",
    "rb-weak-crypto-md5",
    "java-weak-crypto-md5",
    "php-weak-crypto-md5",
    "ex-weak-crypto-md5",
    
    # Basic hardcoded secrets
    "js-hardcoded-secret-password",
    "py-hardcoded-password",
    "rb-hardcoded-password",
    "java-hardcoded-password",
    "php-hardcoded-password",
    
    # Debug/info disclosure
    "rails-debug-mode",
    "django-debug-true",
    "php-display-errors",
    "java-stack-trace-exposure",
    "ex-debug-info",
    "js-debug-console-log",
    
    # Basic open redirect
    "js-open-redirect",
    "py-open-redirect",
    "rb-open-redirect",
    "php-open-redirect",
    
    # Basic insecure random
    "js-insecure-random",
    "py-insecure-random",
    "rb-insecure-random",
    
    # Timing attacks (educational)
    "js-timing-attack-comparison",
    "py-timing-attack",
    "rb-timing-attack"
  ]
  
  # Pattern ID patterns that should be enterprise
  @enterprise_regex_patterns [
    ~r/cve-\d{4}-\d+/i,           # All CVE patterns
    ~r/.*-rce$/,                  # Remote Code Execution
    ~r/.*-xxe-/,                  # XXE patterns
    ~r/.*pickle.*rce/,            # Pickle RCE
    ~r/.*yaml.*rce/,              # YAML RCE
    ~r/.*-ssti$/,                 # Server-Side Template Injection
    ~r/.*template-injection/,
    ~r/ldap-injection/,
    ~r/xpath-injection/,
    ~r/.*struts.*/,               # Struts vulnerabilities
    ~r/.*spring.*rce/,            # Spring vulnerabilities
    ~r/.*jackson.*poly/,          # Jackson polymorphic
    ~r/race-condition/,
    ~r/toctou/,
    ~r/mass-assignment.*admin/,
    ~r/.*traversal.*bypass/,
    ~r/prototype-pollution/,
    ~r/jwt-.*algorithm/,
    ~r/ssrf/,
    ~r/.*deserialization.*rce/
  ]

  def run do
    IO.puts("🚀 Pattern Tier Migration")
    IO.puts("========================\n")
    
    pattern_dirs = [
      "lib/rsolv_api/security/patterns/javascript",
      "lib/rsolv_api/security/patterns/python", 
      "lib/rsolv_api/security/patterns/ruby",
      "lib/rsolv_api/security/patterns/java",
      "lib/rsolv_api/security/patterns/php",
      "lib/rsolv_api/security/patterns/elixir",
      "lib/rsolv_api/security/patterns/rails",
      "lib/rsolv_api/security/patterns/django",
      "lib/rsolv_api/security/patterns/common"
    ]
    
    stats = %{total: 0, migrated: 0, public: 0, ai: 0, enterprise: 0}
    
    stats = Enum.reduce(pattern_dirs, stats, fn dir, acc ->
      case File.ls(dir) do
        {:ok, files} ->
          IO.puts("📁 Processing #{Path.basename(dir)}...")
          process_directory(dir, files, acc)
        {:error, _} ->
          IO.puts("⚠️  Skipping #{dir} (not found)")
          acc
      end
    end)
    
    print_summary(stats)
    save_summary(stats)
  end
  
  defp process_directory(dir, files, stats) do
    pattern_files = Enum.filter(files, &String.ends_with?(&1, ".ex"))
    
    Enum.reduce(pattern_files, stats, fn file, acc ->
      process_pattern_file(Path.join(dir, file), acc)
    end)
  end
  
  defp process_pattern_file(file_path, stats) do
    case File.read(file_path) do
      {:ok, content} ->
        # Extract pattern ID
        pattern_id = extract_pattern_id(content)
        
        if pattern_id do
          stats = Map.update!(stats, :total, &(&1 + 1))
          
          # Determine new tier
          current_tier = extract_current_tier(content)
          new_tier = determine_new_tier(pattern_id, current_tier)
          
          if current_tier != new_tier do
            # Update the file
            updated_content = update_tier_in_content(content, new_tier)
            File.write!(file_path, updated_content)
            
            IO.puts("  ✅ #{pattern_id}: #{current_tier} → #{new_tier}")
            
            stats
            |> Map.update!(:migrated, &(&1 + 1))
            |> Map.update!(String.to_atom(new_tier), &(&1 + 1))
          else
            stats
            |> Map.update!(String.to_atom(new_tier), &(&1 + 1))
          end
        else
          stats
        end
        
      {:error, reason} ->
        IO.puts("  ❌ Error reading #{file_path}: #{reason}")
        stats
    end
  end
  
  defp extract_pattern_id(content) do
    case Regex.run(~r/id:\s*"([^"]+)"/, content) do
      [_, id] -> id
      _ -> nil
    end
  end
  
  defp extract_current_tier(content) do
    case Regex.run(~r/default_tier:\s*:([a-z]+)/, content) do
      [_, tier] -> tier
      _ -> "protected"  # Default if not found
    end
  end
  
  defp determine_new_tier(pattern_id, _current_tier) do
    cond do
      # Check if it's a public pattern
      pattern_id in @public_patterns ->
        "public"
        
      # Check if it matches enterprise patterns
      Enum.any?(@enterprise_regex_patterns, &Regex.match?(&1, pattern_id)) ->
        "enterprise"
        
      # Default to AI (professional) tier
      true ->
        "ai"
    end
  end
  
  defp update_tier_in_content(content, new_tier) do
    Regex.replace(
      ~r/default_tier:\s*:[a-z]+/,
      content,
      "default_tier: :#{new_tier}"
    )
  end
  
  defp print_summary(stats) do
    IO.puts("\n========================")
    IO.puts("📊 Migration Summary")
    IO.puts("========================")
    IO.puts("Total patterns: #{stats.total}")
    IO.puts("Patterns migrated: #{stats.migrated}")
    IO.puts("\nNew Distribution:")
    IO.puts("  🆓 Public (Demo): #{stats.public} patterns")
    IO.puts("  💼 AI (Professional): #{stats.ai} patterns") 
    IO.puts("  🏢 Enterprise: #{stats.enterprise} patterns")
    IO.puts("\n✅ Migration complete!")
  end
  
  defp save_summary(stats) do
    summary = """
    # Pattern Tier Migration Summary
    
    Date: #{DateTime.utc_now() |> DateTime.to_string()}
    
    ## Results
    - Total patterns processed: #{stats.total}
    - Patterns migrated: #{stats.migrated}
    
    ## New Tier Distribution
    - **Public (Free/Demo)**: #{stats.public} patterns
    - **AI (Professional)**: #{stats.ai} patterns
    - **Enterprise**: #{stats.enterprise} patterns
    
    ## Tier Descriptions
    - **Public**: Basic patterns for demos and free users
    - **AI**: Professional tier with common security patterns
    - **Enterprise**: Advanced patterns including CVEs and RCE
    """
    
    File.write!("PATTERN-TIER-MIGRATION.md", summary)
    IO.puts("\n📄 Summary saved to PATTERN-TIER-MIGRATION.md")
  end
end

# Run the migration
PatternTierMigration.run()