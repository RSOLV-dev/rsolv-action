defmodule Rsolv.AST.ConfidenceScorer do
  @moduledoc """
  Calculates confidence scores for security pattern matches based on
  multiple contextual factors.
  
  This module implements a sophisticated scoring system that considers:
  - AST match quality (exact vs partial)
  - Presence of user input
  - Framework protections
  - Code complexity
  - Language-specific factors
  - File context (test vs production)
  - Pattern severity
  """
  
  @doc """
  Calculates a confidence score between 0.0 and 1.0 based on match context.
  
  Higher scores indicate higher confidence that the finding is a real vulnerability.
  """
  def calculate_confidence(context, language, _options \\ %{}) do
    # Start with base confidence based on pattern type
    pattern_type = Map.get(context, :pattern_type, :unknown)
    base_confidence = get_base_confidence(pattern_type)
    
    # Apply various adjustments
    confidence = base_confidence
    |> adjust_for_ast_match(context)
    |> adjust_for_user_input(context)
    |> adjust_for_framework_protection(context)
    |> adjust_for_code_complexity(context)
    |> adjust_for_language(context, language)
    |> adjust_for_file_context(context)
    |> adjust_for_severity(context)
    |> adjust_for_taint_analysis(context)
    
    # Ensure confidence is between 0.0 and 1.0
    max(0.0, min(1.0, confidence))
  end
  
  @doc """
  Provides a human-readable explanation of the confidence calculation.
  """
  def explain_confidence(context, language, options \\ %{}) do
    confidence = calculate_confidence(context, language, options)
    factors = analyze_factors(context, language)
    
    explanation = "Confidence score: #{Float.round(confidence * 100, 1)}%\n\n"
    explanation = explanation <> "Factors:\n"
    
    Enum.reduce(factors, explanation, fn {factor, impact}, acc ->
      acc <> "- #{factor}: #{impact}\n"
    end)
  end
  
  # Private functions
  
  defp get_base_confidence(pattern_type) do
    case pattern_type do
      :code_injection -> 0.8
      :command_injection -> 0.8  # Command injection is serious
      :remote_code_execution -> 0.85
      :rce -> 0.85  # RCE is critical (eval patterns)
      :sql_injection -> 0.75
      :xss -> 0.7
      :hardcoded_secret -> 0.8
      :weak_random -> 0.6
      _ -> 0.65
    end
  end
  
  defp adjust_for_ast_match(confidence, %{ast_match: :exact}), do: confidence
  defp adjust_for_ast_match(confidence, %{ast_match: :partial}), do: confidence * 0.7
  defp adjust_for_ast_match(confidence, _), do: confidence
  
  defp adjust_for_user_input(confidence, context) do
    pattern_type = Map.get(context, :pattern_type)
    has_user_input = Map.get(context, :has_user_input)
    
    case {pattern_type, has_user_input} do
      # Patterns that don't need user input - no penalty
      {:hardcoded_secret, false} -> confidence
      {:weak_crypto, false} -> confidence  
      {:weak_random, false} -> confidence
      {:insecure_random, false} -> confidence
      
      # Critical patterns - minimal penalty even without user input
      {:code_injection, false} -> confidence * 0.95
      {:rce, false} -> confidence * 0.95
      {:remote_code_execution, false} -> confidence * 0.95
      {:command_injection, false} -> confidence * 0.92
      
      # Injection patterns - moderate penalty without user input
      {:sql_injection, false} -> confidence * 0.85
      {:xss, false} -> confidence * 0.85
      {:nosql_injection, false} -> confidence * 0.85
      
      # Confirmed user input - boost confidence
      {_, true} -> confidence * 1.15
      
      # Unknown pattern without user input - small penalty
      {_, false} -> confidence * 0.9
      
      # No information - neutral
      _ -> confidence
    end
  end
  
  defp adjust_for_framework_protection(confidence, %{framework_protection: true}), do: confidence * 0.4
  defp adjust_for_framework_protection(confidence, _), do: confidence
  
  defp adjust_for_code_complexity(confidence, %{code_complexity: :low}), do: confidence * 1.1
  defp adjust_for_code_complexity(confidence, %{code_complexity: :high}), do: confidence * 0.85
  defp adjust_for_code_complexity(confidence, _), do: confidence
  
  defp adjust_for_language(confidence, context, language) do
    case {language, context[:pattern_type]} do
      {"php", :sql_injection} -> confidence * 1.05
      {"javascript", :xss} -> confidence * 1.05
      _ -> confidence
    end
  end
  
  defp adjust_for_file_context(confidence, %{file_path: path}) when is_binary(path) do
    cond do
      String.contains?(path, ["test", "spec", "_test", "_spec"]) -> confidence * 0.3
      String.contains?(path, ["example", "sample", "demo"]) -> confidence * 0.5
      true -> confidence
    end
  end
  defp adjust_for_file_context(confidence, _), do: confidence
  
  defp adjust_for_severity(confidence, context) do
    severity_multiplier = case {context[:pattern_type], context[:function_name], context[:in_database_call]} do
      {:remote_code_execution, _, _} -> 1.15
      {:code_injection, "eval", _} -> 1.2
      {:sql_injection, _, true} -> 1.1
      _ -> 1.0
    end
    
    confidence * severity_multiplier
  end
  
  defp adjust_for_taint_analysis(confidence, %{taint_analysis: %{sanitization_applied: false}}) do
    confidence
  end
  defp adjust_for_taint_analysis(confidence, %{taint_analysis: %{sanitization_applied: true}}) do
    confidence * 0.6
  end
  defp adjust_for_taint_analysis(confidence, _), do: confidence
  
  defp analyze_factors(context, language) do
    factors = []
    
    factors = if context[:has_user_input] do
      [{"User input detected", "increases confidence"} | factors]
    else
      [{"No user input", "decreases confidence"} | factors]
    end
    
    factors = if context[:framework_protection] do
      [{"Framework protection", "significantly decreases confidence"} | factors]
    else
      factors
    end
    
    factors = case context[:ast_match] do
      :exact -> [{"Exact AST match", "high confidence match"} | factors]
      :partial -> [{"Partial AST match", "moderate confidence match"} | factors]
      _ -> factors
    end
    
    factors = if is_binary(context[:file_path]) && String.contains?(context[:file_path], ["test", "spec"]) do
      [{"Test file", "very low confidence in test files"} | factors]
    else
      factors
    end
    
    factors = if language == "php" && context[:pattern_type] == :sql_injection do
      [{"PHP SQL injection", "PHP historically prone to SQL injection"} | factors]
    else
      factors
    end
    
    Enum.reverse(factors)
  end
end