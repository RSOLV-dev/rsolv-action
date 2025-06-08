defmodule RsolvApi.Security.SecurityPattern do
  use Ecto.Schema
  import Ecto.Changeset

  schema "security_patterns" do
    field :name, :string
    field :description, :string
    field :language, :string
    field :type, :string
    field :severity, :string
    field :cwe_id, :string
    field :owasp_category, :string
    field :remediation, :string
    field :confidence, :string, default: "medium"
    field :framework, :string

    # Pattern matching data
    field :regex_patterns, {:array, :string}, default: []
    field :safe_usage_patterns, {:array, :string}, default: []
    field :example_code, :string
    field :fix_template, :string

    # Metadata
    field :is_active, :boolean, default: true
    field :source, :string, default: "rsolv"
    field :tags, {:array, :string}, default: []

    belongs_to :tier, RsolvApi.Security.PatternTier

    timestamps()
  end

  @doc false
  def changeset(security_pattern, attrs) do
    security_pattern
    |> cast(attrs, [:name, :description, :language, :type, :severity, :cwe_id, 
                    :owasp_category, :remediation, :confidence, :framework,
                    :regex_patterns, :safe_usage_patterns, :example_code, 
                    :fix_template, :tier_id, :is_active, :source, :tags])
    |> validate_required([:name, :description, :language, :type, :severity, :tier_id])
    |> validate_inclusion(:severity, ["low", "medium", "high", "critical"])
    |> validate_inclusion(:confidence, ["low", "medium", "high"])
    |> unique_constraint([:name, :language, :type])
    |> foreign_key_constraint(:tier_id)
  end

  @doc """
  Convert pattern data from TypeScript format to database format
  """
  def from_typescript_pattern(pattern_data, tier_name, language) do
    tier_id = get_tier_id_by_name(tier_name)
    
    %{
      name: pattern_data["name"] || Map.get(pattern_data, :name),
      description: pattern_data["description"] || Map.get(pattern_data, :description),
      language: language,
      type: pattern_data["type"] || Map.get(pattern_data, :type),
      severity: pattern_data["severity"] || Map.get(pattern_data, :severity),
      cwe_id: pattern_data["cweId"] || Map.get(pattern_data, :cwe_id),
      owasp_category: pattern_data["owaspCategory"] || Map.get(pattern_data, :owasp_category),
      remediation: pattern_data["remediation"] || Map.get(pattern_data, :remediation),
      confidence: pattern_data["confidence"] || "medium",
      framework: pattern_data["framework"] || Map.get(pattern_data, :framework),
      regex_patterns: extract_regex_patterns(pattern_data),
      safe_usage_patterns: pattern_data["safeUsage"] || pattern_data["safe_usage"] || [],
      example_code: pattern_data["example"] || Map.get(pattern_data, :example),
      fix_template: pattern_data["fixTemplate"] || Map.get(pattern_data, :fix_template),
      tier_id: tier_id,
      is_active: true,
      source: "rsolv",
      tags: pattern_data["tags"] || []
    }
  end

  defp get_tier_id_by_name(tier_name) do
    # In production, this would be a database lookup
    # For now, use hardcoded values that match the migration
    case tier_name do
      "public" -> 1
      "protected" -> 2
      "ai" -> 3
      "enterprise" -> 4
      _ -> 2 # default to protected
    end
  end

  defp extract_regex_patterns(pattern_data) do
    cond do
      is_map(pattern_data) and Map.has_key?(pattern_data, "patterns") ->
        patterns = pattern_data["patterns"]
        if is_map(patterns) and Map.has_key?(patterns, "regex") do
          regex_list = patterns["regex"]
          if is_list(regex_list) do
            Enum.map(regex_list, fn
              %{source: source} -> source
              source when is_binary(source) -> source
              other -> inspect(other)
            end)
          else
            []
          end
        else
          []
        end
      true -> []
    end
  end
end