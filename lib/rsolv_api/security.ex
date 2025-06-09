defmodule RsolvApi.Security do
  @moduledoc """
  The Security context for managing security patterns and tiers.
  Now uses compile-time pattern modules instead of database queries.
  """

  alias RsolvApi.Security.Pattern
  alias RsolvApi.FeatureFlags
  
  # Pattern modules
  @pattern_modules %{
    "javascript" => RsolvApi.Security.Patterns.Javascript,
    "python" => RsolvApi.Security.Patterns.Python,
    "java" => RsolvApi.Security.Patterns.Java,
    "elixir" => RsolvApi.Security.Patterns.Elixir,
    "php" => RsolvApi.Security.Patterns.Php,
    "ruby" => RsolvApi.Security.Patterns.Ruby
  }
  
  # Framework-specific modules
  @framework_modules %{
    "django" => RsolvApi.Security.Patterns.Django,
    "rails" => RsolvApi.Security.Patterns.Rails
  }
  
  # Cross-language patterns (CVEs)
  @cve_module RsolvApi.Security.Patterns.Cve

  @doc """
  Returns the list of security patterns for a given language and tier.
  Now uses compile-time pattern modules.
  """
  def list_patterns_by_language_and_tier(language, tier_name) do
    patterns = get_patterns_for_language(language)
    
    # Filter by tier
    Enum.filter(patterns, fn pattern ->
      get_pattern_tier(pattern) == tier_name
    end)
  end

  @doc """
  Returns the list of security patterns for a given language with tier filtering.
  Now uses compile-time pattern modules.
  """
  def list_patterns_by_language(language, accessible_tiers \\ ["public"]) do
    patterns = get_patterns_for_language(language)
    
    # Filter by accessible tiers
    patterns
    |> Enum.filter(fn pattern ->
      get_pattern_tier(pattern) in accessible_tiers
    end)
    |> Enum.sort_by(fn pattern ->
      {severity_order(pattern.severity), pattern.name}
    end)
  end

  @doc """
  Returns all patterns for a specific tier (cross-language).
  """
  def list_patterns_by_tier(tier_name) do
    all_languages = Map.keys(@pattern_modules)
    framework_names = Map.keys(@framework_modules)
    
    # Get patterns from all language modules
    language_patterns = Enum.flat_map(all_languages, fn language ->
      get_patterns_for_language(language)
    end)
    
    # Get framework patterns if enabled
    framework_patterns = if FeatureFlags.enabled?("patterns.include_framework_patterns") do
      Enum.flat_map(framework_names, fn framework ->
        case Map.get(@framework_modules, framework) do
          nil -> []
          module -> apply(module, :all, [])
        end
      end)
    else
      []
    end
    
    # Get CVE patterns if enabled
    cve_patterns = if FeatureFlags.enabled?("patterns.include_cve_patterns") do
      apply(@cve_module, :all, [])
    else
      []
    end
    
    # Combine all patterns and filter by tier
    all_patterns = language_patterns ++ framework_patterns ++ cve_patterns
    
    all_patterns
    |> Enum.filter(fn pattern ->
      get_pattern_tier(pattern) == tier_name
    end)
    |> Enum.uniq_by(& &1.id)  # Remove duplicates
    |> Enum.sort_by(fn pattern ->
      {severity_order(pattern.severity), pattern.name}
    end)
  end

  @doc """
  Returns all patterns based on accessible tiers (cross-language).
  """
  def list_all_patterns(accessible_tiers \\ ["public"]) do
    all_languages = Map.keys(@pattern_modules)
    framework_names = Map.keys(@framework_modules)
    
    # Get patterns from all language modules
    language_patterns = Enum.flat_map(all_languages, fn language ->
      get_patterns_for_language(language)
    end)
    
    # Get framework patterns if enabled
    framework_patterns = if FeatureFlags.enabled?("patterns.include_framework_patterns") do
      Enum.flat_map(framework_names, fn framework ->
        case Map.get(@framework_modules, framework) do
          nil -> []
          module -> apply(module, :all, [])
        end
      end)
    else
      []
    end
    
    # Get CVE patterns if enabled
    cve_patterns = if FeatureFlags.enabled?("patterns.include_cve_patterns") do
      apply(@cve_module, :all, [])
    else
      []
    end
    
    # Combine all patterns and filter by accessible tiers
    all_patterns = language_patterns ++ framework_patterns ++ cve_patterns
    
    all_patterns
    |> Enum.filter(fn pattern ->
      get_pattern_tier(pattern) in accessible_tiers
    end)
    |> Enum.uniq_by(& &1.id)  # Remove duplicates
    |> Enum.sort_by(fn pattern ->
      {severity_order(pattern.severity), pattern.name}
    end)
  end


  @doc """
  Get accessible tiers based on authentication and authorization.
  Now uses feature flags for dynamic tier access control.
  """
  def get_accessible_tiers(api_key \\ nil, customer \\ nil, _ai_enabled \\ false) do
    # Use feature flags to determine accessible tiers
    if FeatureFlags.enabled?("patterns.use_compiled_modules") do
      FeatureFlags.get_accessible_tiers(customer)
    else
      # Fallback to original logic if feature flag is disabled
      cond do
        # Enterprise customer
        customer && customer.tier == "enterprise" ->
          ["public", "protected", "ai", "enterprise"]

        # API key with AI access
        api_key && customer ->
          ["public", "protected", "ai"]

        # API key without AI access
        api_key ->
          ["public", "protected"]

        # No authentication
        true ->
          ["public"]
      end
    end
  end

  @doc """
  Convert patterns to API response format.
  Updated to work with Pattern struct from modules.
  """
  def format_patterns_for_api(patterns) do
    Enum.map(patterns, fn pattern ->
      %{
        id: pattern.id,
        name: pattern.name,
        description: pattern.description,
        type: pattern.type,
        severity: pattern.severity,
        cweId: pattern.cwe_id,
        owaspCategory: pattern.owasp_category,
        recommendation: pattern.recommendation,
        frameworks: pattern.frameworks || [],
        languages: pattern.languages,
        patterns: %{
          regex: format_regex(pattern.regex)
        },
        testCases: pattern.test_cases
      }
    end)
  end
  
  # Helper functions for compile-time patterns
  
  defp get_patterns_for_language(language) do
    language_lower = String.downcase(language)
    
    # Get language-specific patterns
    language_patterns = case Map.get(@pattern_modules, language_lower) do
      nil -> []
      module -> apply(module, :all, [])
    end
    
    # Get framework-specific patterns if enabled
    framework_patterns = if FeatureFlags.enabled?("patterns.include_framework_patterns") do
      case Map.get(@framework_modules, language_lower) do
        nil -> []
        module -> apply(module, :all, [])
      end
    else
      []
    end
    
    # Add CVE patterns if enabled (they apply to all languages)
    cve_patterns = if FeatureFlags.enabled?("patterns.include_cve_patterns") do
      apply(@cve_module, :all, [])
    else
      []
    end
    
    language_patterns ++ framework_patterns ++ cve_patterns
  end
  
  defp get_pattern_tier(%Pattern{} = pattern) do
    # Use the default_tier or determine based on pattern characteristics
    tier = pattern.default_tier || determine_tier_from_pattern(pattern)
    # Convert atom to string for API compatibility
    to_string(tier)
  end
  
  defp determine_tier_from_pattern(%Pattern{} = pattern) do
    cond do
      # Critical/high severity patterns are protected
      pattern.severity in [:critical, :high] -> :protected
      
      # AI/ML related patterns
      String.contains?(pattern.name, ["AI", "ML", "LLM"]) -> :ai
      
      # Basic patterns can be public
      pattern.severity == :low -> :public
      
      # Default to protected
      true -> :protected
    end
  end
  
  defp severity_order(:critical), do: 0
  defp severity_order(:high), do: 1
  defp severity_order(:medium), do: 2
  defp severity_order(:low), do: 3
  
  defp format_regex(regex) when is_list(regex) do
    Enum.map(regex, &Regex.source/1)
  end
  defp format_regex(%Regex{} = regex) do
    [Regex.source(regex)]
  end

end