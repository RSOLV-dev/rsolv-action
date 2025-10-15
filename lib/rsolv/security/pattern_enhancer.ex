defmodule Rsolv.Security.PatternEnhancer do
  @moduledoc """
  Simple pattern enhancement to reduce false positives.

  Takes existing patterns and adds minimal context rules
  without changing the core structure.
  """

  @doc """
  Enhance patterns with context rules based on their type.

  ## Examples

      iex> pattern = %Pattern{id: "js-sql-injection", type: "sql_injection"}
      iex> enhanced = PatternEnhancer.enhance(pattern)
      iex> enhanced.exclude_paths
      ["test", "spec", "__tests__", "node_modules"]
  """
  def enhance(patterns) when is_list(patterns) do
    Enum.map(patterns, &enhance/1)
  end

  def enhance(%{type: "sql_injection"} = pattern) do
    pattern
    |> Map.put(:exclude_paths, ["test", "spec", "__tests__", "node_modules"])
    |> Map.put(:confidence_modifier, fn code ->
      cond do
        # Parameterized query? Very likely safe
        String.contains?(code, "?") -> -0.8
        # Using an ORM method? Probably safe
        String.match?(code, ~r/\.(where|select|join)\(/) -> -0.5
        # Direct string concatenation? More suspicious
        String.contains?(code, "${") -> 0.2
        true -> 0
      end
    end)
  end

  def enhance(%{type: "logging"} = pattern) do
    pattern
    |> Map.put(:exclude_paths, ["test", "spec", "mock", "stub", "__tests__"])
    # Lower confidence for logging patterns
    |> Map.put(:base_confidence, 0.6)
    |> Map.put(:exclude_patterns, [
      # Exclude if logging exists anywhere nearby
      ~r/\b(log|logger|console\.log|audit)\b/i,
      # Exclude test helpers
      ~r/\b(mock|stub|fake|spy)\b/i
    ])
  end

  def enhance(%{type: "nosql_injection"} = pattern) do
    pattern
    |> Map.put(:exclude_paths, ["test", "spec"])
    |> Map.put(:safe_method_names, [
      # Mongoose methods that sanitize by default
      "findById",
      "findByIdAndUpdate",
      "findByIdAndDelete"
    ])
  end

  # Default enhancement for other patterns
  def enhance(pattern) do
    pattern
    |> Map.put(:exclude_paths, ["test", "spec", "node_modules"])
  end

  @doc """
  Check if enhanced patterns are enabled via config.
  """
  def enabled? do
    Application.get_env(:rsolv, :enhanced_patterns, false)
  end
end
