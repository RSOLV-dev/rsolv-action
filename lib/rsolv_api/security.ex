defmodule RsolvApi.Security do
  @moduledoc """
  The Security context for managing security patterns and tiers.
  """

  import Ecto.Query, warn: false
  alias RsolvApi.Repo

  alias RsolvApi.Security.{SecurityPattern, PatternTier}

  @doc """
  Returns the list of security patterns for a given language and tier.
  """
  def list_patterns_by_language_and_tier(language, tier_name) do
    query = from p in SecurityPattern,
      join: t in PatternTier, on: p.tier_id == t.id,
      where: p.language == ^language and t.name == ^tier_name and p.is_active == true,
      select: p

    Repo.all(query)
  end

  @doc """
  Returns the list of security patterns for a given language with tier filtering.
  """
  def list_patterns_by_language(language, accessible_tiers \\ ["public"]) do
    query = from p in SecurityPattern,
      join: t in PatternTier, on: p.tier_id == t.id,
      where: p.language == ^language and t.name in ^accessible_tiers and p.is_active == true,
      order_by: [asc: t.display_order, asc: p.severity, asc: p.name],
      preload: [:tier]

    Repo.all(query)
  end

  @doc """
  Gets a single security pattern.
  """
  def get_security_pattern!(id), do: Repo.get!(SecurityPattern, id)

  @doc """
  Creates a security pattern.
  """
  def create_security_pattern(attrs \\ %{}) do
    %SecurityPattern{}
    |> SecurityPattern.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Bulk insert security patterns from TypeScript pattern files.
  """
  def bulk_insert_patterns(patterns_by_language, tier_assignments \\ %{}) do
    Repo.transaction(fn ->
      for {language, patterns} <- patterns_by_language do
        for pattern <- patterns do
          tier_name = determine_tier(pattern, tier_assignments, language)
          pattern_attrs = SecurityPattern.from_typescript_pattern(pattern, tier_name, language)
          
          case create_security_pattern(pattern_attrs) do
            {:ok, _pattern} -> :ok
            {:error, changeset} -> 
              IO.puts("Failed to insert pattern #{pattern_attrs.name}: #{inspect(changeset.errors)}")
          end
        end
      end
    end)
  end

  @doc """
  Determine which tier a pattern should be assigned to based on various criteria.
  """
  def determine_tier(pattern, tier_assignments, language) do
    pattern_name = pattern["name"] || pattern.name
    pattern_type = pattern["type"] || pattern.type
    severity = pattern["severity"] || pattern.severity

    cond do
      # Check explicit tier assignments
      Map.has_key?(tier_assignments, pattern_name) ->
        tier_assignments[pattern_name]

      # AI-specific patterns
      String.contains?(pattern_name || "", ["AI", "ML", "LLM"]) or
      String.contains?(pattern_type || "", ["ai", "ml", "llm"]) ->
        "ai"

      # High severity or CVE patterns go to protected
      severity == "critical" or severity == "high" or
      String.contains?(pattern_name || "", "CVE") ->
        "protected"

      # Basic patterns that can be public for trust building
      severity == "low" or
      pattern_type in ["xss", "sql_injection", "hardcoded_secret"] ->
        "public"

      # Everything else goes to protected
      true ->
        "protected"
    end
  end

  @doc """
  Get accessible tiers based on authentication and authorization.
  """
  def get_accessible_tiers(api_key \\ nil, customer \\ nil, ai_enabled \\ false) do
    cond do
      # Enterprise customer
      customer && customer.tier == "enterprise" ->
        ["public", "protected", "ai", "enterprise"]

      # API key with AI access
      api_key && ai_enabled ->
        ["public", "protected", "ai"]

      # API key without AI access
      api_key ->
        ["public", "protected"]

      # No authentication
      true ->
        ["public"]
    end
  end

  @doc """
  Convert patterns to API response format.
  """
  def format_patterns_for_api(patterns) do
    Enum.map(patterns, fn pattern ->
      %{
        name: pattern.name,
        description: pattern.description,
        type: pattern.type,
        severity: pattern.severity,
        cweId: pattern.cwe_id,
        owaspCategory: pattern.owasp_category,
        remediation: pattern.remediation,
        confidence: pattern.confidence,
        framework: pattern.framework,
        patterns: %{
          regex: pattern.regex_patterns
        },
        safeUsage: pattern.safe_usage_patterns,
        example: pattern.example_code,
        fixTemplate: pattern.fix_template,
        tags: pattern.tags
      }
    end)
  end

  @doc """
  Returns the list of pattern tiers.
  """
  def list_pattern_tiers do
    Repo.all(PatternTier)
  end

  @doc """
  Gets a single pattern tier.
  """
  def get_pattern_tier!(id), do: Repo.get!(PatternTier, id)

  @doc """
  Gets a pattern tier by name.
  """
  def get_pattern_tier_by_name(name) do
    Repo.get_by(PatternTier, name: name)
  end
end