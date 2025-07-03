defmodule Rsolv.Security do
  @moduledoc """
  The Security context for managing security patterns and tiers.
  Now uses compile-time pattern modules instead of database queries.
  Supports both standard and enhanced patterns for AST-based scanning.
  """

  alias Rsolv.Security.Pattern
  alias Rsolv.Security.EnhancedPattern
  alias Rsolv.FeatureFlags
  
  # Pattern modules
  @pattern_modules %{
    "javascript" => Rsolv.Security.Patterns.Javascript,
    "python" => Rsolv.Security.Patterns.Python,
    "java" => Rsolv.Security.Patterns.Java,
    "elixir" => Rsolv.Security.Patterns.Elixir,
    "php" => Rsolv.Security.Patterns.Php,
    "ruby" => Rsolv.Security.Patterns.Ruby
  }
  
  # Enhanced pattern modules (with AST support)
  @enhanced_pattern_modules %{
    "javascript" => Rsolv.Security.Patterns.JavascriptEnhanced
  }
  
  # Framework-specific modules
  @framework_modules %{
    "django" => Rsolv.Security.Patterns.Django,
    "rails" => Rsolv.Security.Patterns.Rails
  }
  
  # Cross-language patterns (CVEs)
  @cve_module Rsolv.Security.Patterns.Cve

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
  Returns the list of security patterns for a given language.
  Now uses compile-time pattern modules.
  """
  def list_patterns_by_language(language) do
    patterns = get_patterns_for_language(language)
    
    # Return all patterns without tier filtering
    patterns
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
        tier: to_string(get_pattern_tier(pattern)),
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
  
  @doc """
  Convert patterns to enhanced API response format with AST rules.
  Supports both standard Pattern and EnhancedPattern structs.
  """
  def format_patterns_for_enhanced_api(patterns, include_enhanced \\ true) do
    Enum.map(patterns, fn pattern ->
      case pattern do
        %EnhancedPattern{} when include_enhanced ->
          EnhancedPattern.to_enhanced_api_format(pattern)
          
        %EnhancedPattern{} ->
          # Convert to standard format if enhanced not requested
          pattern |> EnhancedPattern.to_pattern() |> format_single_pattern()
          
        %Pattern{} ->
          format_single_pattern(pattern)
      end
    end)
  end
  
  defp format_single_pattern(pattern) do
    %{
      id: pattern.id,
      name: pattern.name,
      description: pattern.description,
      type: pattern.type,
      severity: pattern.severity,
      tier: to_string(get_pattern_tier(pattern)),
      cweId: pattern.cwe_id,
      owaspCategory: pattern.owasp_category,
      recommendation: pattern.recommendation,
      frameworks: pattern.frameworks || [],
      languages: pattern.languages,
      patterns: %{
        regex: format_regex(pattern.regex)
      },
      testCases: pattern.test_cases,
      supports_ast: false
    }
  end
  
  # Helper functions for compile-time patterns
  
  defp get_patterns_for_language(language) do
    language_lower = String.downcase(language)
    
    # Get language-specific patterns
    language_patterns = case Map.get(@pattern_modules, language_lower) do
      nil -> []
      module -> apply(module, :all, [])
    end
    
    # Get enhanced patterns if enabled
    enhanced_patterns = if FeatureFlags.enabled?("patterns.use_enhanced_patterns") do
      case Map.get(@enhanced_pattern_modules, language_lower) do
        nil -> []
        module -> 
          # Enhanced modules can return EnhancedPattern structs
          # Enhanced modules may require tier argument, use :enterprise to get all patterns
          enhanced = apply(module, :all, [:enterprise])
          # Convert to Pattern structs for backward compatibility
          Enum.map(enhanced, fn pattern ->
            case pattern do
              %EnhancedPattern{} -> EnhancedPattern.to_pattern(pattern)
              %Pattern{} -> pattern
            end
          end)
      end
    else
      []
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
    
    # Combine all patterns, with enhanced patterns taking precedence
    all_patterns = enhanced_patterns ++ language_patterns ++ framework_patterns ++ cve_patterns
    
    # Remove duplicates by ID (enhanced patterns override standard ones)
    all_patterns
    |> Enum.uniq_by(& &1.id)
  end
  
  @doc """
  Get enhanced patterns for a language including AST rules.
  Returns both EnhancedPattern and Pattern structs.
  """
  def get_enhanced_patterns_for_language(language) do
    language_lower = String.downcase(language)
    
    # Get enhanced patterns
    enhanced_patterns = case Map.get(@enhanced_pattern_modules, language_lower) do
      nil -> []
      module -> 
        # Enhanced modules may require tier argument, use :enterprise to get all patterns
        apply(module, :all, [:enterprise])
    end
    
    # Get standard patterns
    standard_patterns = case Map.get(@pattern_modules, language_lower) do
      nil -> []
      module -> apply(module, :all, [])
    end
    
    # Combine, with enhanced taking precedence
    enhanced_ids = enhanced_patterns |> Enum.map(& &1.id) |> MapSet.new()
    
    filtered_standard = standard_patterns
    |> Enum.reject(fn pattern -> MapSet.member?(enhanced_ids, pattern.id) end)
    
    enhanced_patterns ++ filtered_standard
  end
  
  defp get_pattern_tier(pattern) do
    # Determine tier based on pattern characteristics
    tier = determine_tier_from_pattern(pattern)
    # Convert atom to string for API compatibility
    to_string(tier)
  end
  
  defp determine_tier_from_pattern(pattern) do
    # Works with both Pattern and EnhancedPattern
    severity = pattern.severity
    name = pattern.name
    
    cond do
      # Critical/high severity patterns are protected
      severity in [:critical, :high] -> :protected
      
      # AI/ML related patterns
      String.contains?(name, ["AI", "ML", "LLM"]) -> :ai
      
      # Basic patterns can be public
      severity == :low -> :public
      
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