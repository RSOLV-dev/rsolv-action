defmodule RsolvApi.Security.EnhancedPattern do
  @moduledoc """
  Enhanced pattern structure for AST-based security scanning.
  
  This module extends the basic Pattern structure to support:
  - AST node matching configuration
  - Context-aware rules
  - Confidence scoring
  - Backward compatibility with regex patterns
  """
  
  alias RsolvApi.Security.Pattern
  
  @type ast_node_type :: :call_expression | :member_expression | :identifier | 
                         :literal | :binary_expression | :assignment | :function_declaration |
                         :variable_declaration | :import_declaration | :export_declaration |
                         :if_statement | :for_statement | :while_statement | :try_statement
  
  @type ast_match_rule :: %{
    node_type: ast_node_type(),
    properties: map(),
    parent_context: ast_node_type() | nil,
    child_must_contain: [String.t()] | nil
  }
  
  @type context_rule :: %{
    exclude_paths: [String.t()] | nil,
    exclude_if_contains: [String.t()] | nil,
    require_imports: [String.t()] | nil,
    require_context: [String.t()] | nil
  }
  
  @type confidence_rule :: %{
    base_confidence: float(),
    increase_if: [map()],
    decrease_if: [map()]
  }
  
  @type t :: %__MODULE__{
    # All fields from Pattern
    id: String.t(),
    name: String.t(),
    description: String.t(),
    type: Pattern.vulnerability_type(),
    severity: Pattern.severity(),
    languages: [String.t()],
    frameworks: [String.t()] | nil,
    regex: Regex.t() | [Regex.t()] | nil,  # Made optional for AST-only patterns
    default_tier: Pattern.tier(),
    cwe_id: String.t() | nil,
    owasp_category: String.t() | nil,
    recommendation: String.t(),
    test_cases: %{
      vulnerable: [String.t()],
      safe: [String.t()]
    },
    # Enhanced fields
    ast_rules: [ast_match_rule()] | nil,
    context_rules: context_rule() | nil,
    confidence_rules: confidence_rule() | nil,
    enhanced_recommendation: %{
      quick_fix: String.t() | nil,
      detailed_steps: [String.t()] | nil,
      references: [String.t()] | nil
    } | nil,
    metadata: map() | nil
  }
  
  @enforce_keys [
    :id, :name, :description, :type, :severity,
    :languages, :default_tier, :recommendation,
    :test_cases
  ]
  
  defstruct [
    :id,
    :name,
    :description,
    :type,
    :severity,
    :languages,
    :frameworks,
    :regex,
    :default_tier,
    :cwe_id,
    :owasp_category,
    :recommendation,
    :test_cases,
    :ast_rules,
    :context_rules,
    :confidence_rules,
    :enhanced_recommendation,
    :metadata
  ]
  
  @doc """
  Converts an enhanced pattern to the standard Pattern struct for backward compatibility.
  """
  def to_pattern(%__MODULE__{} = enhanced) do
    %Pattern{
      id: enhanced.id,
      name: enhanced.name,
      description: enhanced.description,
      type: enhanced.type,
      severity: enhanced.severity,
      languages: enhanced.languages,
      frameworks: enhanced.frameworks,
      regex: enhanced.regex || build_fallback_regex(enhanced),
      default_tier: enhanced.default_tier,
      cwe_id: enhanced.cwe_id,
      owasp_category: enhanced.owasp_category,
      recommendation: enhanced.recommendation,
      test_cases: enhanced.test_cases
    }
  end
  
  @doc """
  Converts an enhanced pattern to the extended API format including AST rules.
  """
  def to_enhanced_api_format(%__MODULE__{} = pattern) do
    base_format = Pattern.to_api_format(to_pattern(pattern))
    
    Map.merge(base_format, %{
      ast_rules: pattern.ast_rules,
      context_rules: pattern.context_rules,
      confidence_rules: pattern.confidence_rules,
      enhanced_recommendation: pattern.enhanced_recommendation,
      metadata: pattern.metadata,
      supports_ast: pattern.ast_rules != nil
    })
  end
  
  @doc """
  Validates an enhanced pattern has all required fields and valid values.
  """
  def valid?(%__MODULE__{} = pattern) do
    # Must have either regex or AST rules
    has_detection_method = pattern.regex != nil || pattern.ast_rules != nil
    
    # Validate base pattern fields
    base_valid = Pattern.valid?(to_pattern(pattern))
    
    # Validate enhanced fields
    ast_valid = validate_ast_rules(pattern.ast_rules)
    context_valid = validate_context_rules(pattern.context_rules)
    confidence_valid = validate_confidence_rules(pattern.confidence_rules)
    
    has_detection_method && base_valid && ast_valid && context_valid && confidence_valid
  end
  
  # Private validation functions
  
  defp validate_ast_rules(nil), do: true
  defp validate_ast_rules(rules) when is_list(rules) do
    Enum.all?(rules, &validate_single_ast_rule/1)
  end
  defp validate_ast_rules(_), do: false
  
  defp validate_single_ast_rule(%{node_type: type, properties: props}) 
    when is_atom(type) and is_map(props), do: true
  defp validate_single_ast_rule(_), do: false
  
  defp validate_context_rules(nil), do: true
  defp validate_context_rules(%{} = rules) do
    valid_keys = [:exclude_paths, :exclude_if_contains, :require_imports, :require_context]
    Map.keys(rules) |> Enum.all?(&(&1 in valid_keys))
  end
  defp validate_context_rules(_), do: false
  
  defp validate_confidence_rules(nil), do: true
  defp validate_confidence_rules(%{base_confidence: base} = rules) 
    when is_float(base) and base >= 0.0 and base <= 1.0 do
    valid_modifiers = 
      validate_confidence_modifiers(Map.get(rules, :increase_if, [])) &&
      validate_confidence_modifiers(Map.get(rules, :decrease_if, []))
    
    valid_modifiers
  end
  defp validate_confidence_rules(_), do: false
  
  defp validate_confidence_modifiers(modifiers) when is_list(modifiers) do
    Enum.all?(modifiers, fn mod ->
      is_map(mod) && Map.has_key?(mod, :condition) && Map.has_key?(mod, :amount)
    end)
  end
  defp validate_confidence_modifiers(_), do: false
  
  # Fallback regex generation for AST-only patterns
  defp build_fallback_regex(%__MODULE__{ast_rules: rules}) when is_list(rules) do
    # Generate a simple regex based on AST rules for backward compatibility
    # This is a basic implementation - can be enhanced based on specific needs
    keywords = extract_keywords_from_ast_rules(rules)
    
    if length(keywords) > 0 do
      pattern = keywords |> Enum.join("|")
      ~r/#{pattern}/i
    else
      nil
    end
  end
  defp build_fallback_regex(_), do: nil
  
  defp extract_keywords_from_ast_rules(rules) do
    Enum.flat_map(rules, fn rule ->
      case rule do
        %{properties: %{name: name}} when is_binary(name) -> [name]
        %{properties: %{value: value}} when is_binary(value) -> [value]
        %{properties: %{callee: %{name: name}}} when is_binary(name) -> [name]
        _ -> []
      end
    end)
    |> Enum.uniq()
  end
end