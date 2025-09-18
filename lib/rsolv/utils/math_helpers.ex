defmodule Rsolv.Utils.MathHelpers do
  @moduledoc """
  Type-safe mathematical helper functions to prevent runtime errors.
  """

  @doc """
  Safely calculates a percentage, always returning a float.

  ## Examples

      iex> Rsolv.Utils.MathHelpers.safe_percentage(50, 100)
      50.0

      iex> Rsolv.Utils.MathHelpers.safe_percentage(0, 0)
      0.0

      iex> Rsolv.Utils.MathHelpers.safe_percentage(10, 0)
      0.0

  """
  @spec safe_percentage(number(), number()) :: float()
  def safe_percentage(_numerator, 0), do: 0.0
  def safe_percentage(_numerator, 0.0), do: 0.0
  def safe_percentage(numerator, denominator) when is_number(numerator) and is_number(denominator) do
    # Convert to float and multiply by 100 for percentage
    (numerator * 100.0) / denominator
  end

  @doc """
  Safely rounds a number to specified decimal places.
  Always ensures the input is a float to prevent Float.round runtime errors.

  ## Examples

      iex> Rsolv.Utils.MathHelpers.safe_round(10, 2)
      10.0

      iex> Rsolv.Utils.MathHelpers.safe_round(10.567, 2)
      10.57

      iex> Rsolv.Utils.MathHelpers.safe_round(0, 2)
      0.0

  """
  @spec safe_round(number(), non_neg_integer()) :: float()
  def safe_round(number, precision \\ 2) when is_number(number) and is_integer(precision) and precision >= 0 do
    # Ensure number is a float before calling Float.round
    Float.round(number / 1.0, precision)
  end

  @doc """
  Safely calculates a rate (e.g., cache hit rate, success rate).
  Returns a rounded percentage.

  ## Examples

      iex> Rsolv.Utils.MathHelpers.safe_rate(75, 100)
      75.0

      iex> Rsolv.Utils.MathHelpers.safe_rate(0, 0)
      0.0

  """
  @spec safe_rate(number(), number(), non_neg_integer()) :: float()
  def safe_rate(hits, total, precision \\ 2) do
    hits
    |> safe_percentage(total)
    |> safe_round(precision)
  end
end