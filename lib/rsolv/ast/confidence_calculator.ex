defmodule Rsolv.AST.ConfidenceCalculator do
  @moduledoc """
  Enhanced confidence calculation that works with pattern-specific rules
  and provides boosts for exact AST structural matches.
  
  This module bridges between the pattern matcher and the ConfidenceScorer,
  providing additional context-aware confidence adjustments.
  """
  
  alias Rsolv.AST.ConfidenceScorer
  
  @doc """
  Calculates confidence for a pattern match, taking into account
  pattern-specific rules and exact structural matches.
  """
  def calculate_confidence(pattern, node, context, confidence_rules \\ %{}) do
    # Start with base confidence from rules or default
    base = Map.get(confidence_rules, :base, 0.5)
    adjustments = Map.get(confidence_rules, :adjustments, %{})
    
    # Calculate initial confidence
    confidence = base
    
    # Apply adjustments based on pattern and node matching
    confidence = confidence
    |> apply_object_property_bonus(pattern, node, adjustments)
    |> apply_argument_analysis_bonus(pattern, node, adjustments)
    |> apply_user_input_detection(node, adjustments)
    |> apply_context_adjustments(context, adjustments)
    |> apply_test_file_penalty(context, adjustments)
    
    # Ensure confidence is between 0.0 and 1.0
    max(0.0, min(1.0, confidence))
  end
  
  # Private functions
  
  defp apply_object_property_bonus(confidence, pattern, node, adjustments) do
    # Check if pattern has object.property requirements
    object_req = pattern["_callee_object"]
    property_req = pattern["_callee_property"]
    
    if object_req && property_req do
      # Check if node matches the exact object.property
      case node["callee"] do
        %{"type" => "MemberExpression", "object" => %{"name" => actual_obj}, "property" => %{"name" => actual_prop}} ->
          if actual_obj == object_req && actual_prop == property_req do
            # Exact match! Give significant boost
            boost = Map.get(adjustments, "exact_object_property_match", 0.4)
            confidence + boost
          else
            # Not a match, reduce confidence significantly
            confidence * 0.3
          end
          
        _ ->
          # Wrong structure, very low confidence
          confidence * 0.2
      end
    else
      confidence
    end
  end
  
  defp apply_argument_analysis_bonus(confidence, _pattern, node, adjustments) do
    # Check for weak crypto algorithms in arguments
    case node["arguments"] do
      [%{"type" => "Literal", "value" => value}] when is_binary(value) ->
        if Regex.match?(~r/^(md5|sha-?1)$/i, value) do
          boost = Map.get(adjustments, "has_weak_algorithm", 0.2)
          confidence + boost
        else
          confidence
        end
        
      _ ->
        confidence
    end
  end
  
  defp apply_user_input_detection(confidence, node, adjustments) do
    # Check if the node involves user input variables or parameters
    user_input_indicators = ["user_input", "request", "params", "argv", "args", "input", "data", "body", "query", "cmd", "command"]
    
    has_user_input = case node do
      %{"arguments" => args} when is_list(args) ->
        # Check arguments for user input variables
        Enum.any?(args, fn arg ->
          case arg do
            %{"type" => "Name", "id" => name} ->
              # Check if variable name suggests user input or command construction
              Enum.any?(user_input_indicators, &String.contains?(String.downcase(name), &1))
            %{"type" => "Identifier", "name" => name} ->
              Enum.any?(user_input_indicators, &String.contains?(String.downcase(name), &1))
            %{"type" => "BinOp"} ->
              # String concatenation in argument - likely dynamic construction
              true
            _ -> false
          end
        end)
      
      %{"type" => "BinOp", "right" => %{"type" => "Name", "id" => name}} ->
        # Python binary operations with user input
        Enum.any?(user_input_indicators, &String.contains?(String.downcase(name), &1))
        
      %{"type" => "BinaryExpression", "right" => %{"type" => "Identifier", "name" => name}} ->
        # JavaScript binary expressions with user input
        Enum.any?(user_input_indicators, &String.contains?(String.downcase(name), &1))
        
      _ -> false
    end
    
    if has_user_input do
      boost = Map.get(adjustments, "has_user_input", 0.3)
      confidence + boost
    else
      confidence
    end
  end
  
  defp apply_context_adjustments(confidence, context, adjustments) do
    confidence
    |> apply_depth_adjustment(context, adjustments)
    |> apply_parent_type_adjustment(context, adjustments)
  end
  
  defp apply_depth_adjustment(confidence, %{depth: depth}, _adjustments) when depth > 10 do
    # Very deep nesting might indicate less relevant code
    confidence * 0.9
  end
  defp apply_depth_adjustment(confidence, _context, _adjustments), do: confidence
  
  defp apply_parent_type_adjustment(confidence, %{parent_type: "VariableDeclarator"}, adjustments) do
    # Being assigned to a variable is a common pattern for crypto operations
    boost = Map.get(adjustments, "in_variable_declaration", 0.05)
    confidence + boost
  end
  defp apply_parent_type_adjustment(confidence, _context, _adjustments), do: confidence
  
  defp apply_test_file_penalty(confidence, %{in_test_file: true}, adjustments) do
    penalty = Map.get(adjustments, "in_test_code", -0.6)
    confidence + penalty
  end
  defp apply_test_file_penalty(confidence, _context, _adjustments), do: confidence
  
  @doc """
  Integrates with the existing ConfidenceScorer for a combined score.
  
  This allows us to leverage both the pattern-specific rules and
  the general confidence scoring logic.
  """
  def calculate_combined_confidence(pattern, node, context, confidence_rules, language, options \\ %{}) do
    # Get pattern-specific confidence
    pattern_confidence = calculate_confidence(pattern, node, context, confidence_rules)
    
    # Build context for ConfidenceScorer
    scorer_context = Map.merge(context, %{
      pattern_type: determine_pattern_type(pattern),
      ast_match: :exact,
      has_user_input: false  # Will be determined by scorer
    })
    
    # Get general confidence score
    general_confidence = ConfidenceScorer.calculate_confidence(scorer_context, language, options)
    
    # Weight the scores (70% pattern-specific, 30% general)
    weighted = (pattern_confidence * 0.7) + (general_confidence * 0.3)
    
    # Ensure final confidence is between 0.0 and 1.0
    max(0.0, min(1.0, weighted))
  end
  
  defp determine_pattern_type(%{"type" => type}) when is_binary(type) do
    cond do
      String.contains?(type, "crypto") -> :weak_crypto
      String.contains?(type, "injection") -> :injection
      String.contains?(type, "xss") -> :xss
      true -> :unknown
    end
  end
  defp determine_pattern_type(_), do: :unknown
end