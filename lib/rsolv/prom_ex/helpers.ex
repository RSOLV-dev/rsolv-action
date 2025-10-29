defmodule Rsolv.PromEx.Helpers do
  @moduledoc """
  Shared helper functions for PromEx plugins.

  Provides common utilities for tag extraction and value formatting
  to ensure consistency across all custom PromEx plugins.
  """

  @doc """
  Safely converts a value to a string for use as a Prometheus tag.

  Returns "unknown" for nil or unsupported types to maintain
  consistent metric cardinality.

  ## Examples

      iex> to_string_safe("test")
      "test"

      iex> to_string_safe(:completed)
      "completed"

      iex> to_string_safe(123)
      "123"

      iex> to_string_safe(nil)
      "unknown"
  """
  def to_string_safe(value) when is_binary(value), do: value
  def to_string_safe(value) when is_atom(value), do: Atom.to_string(value)
  def to_string_safe(value) when is_integer(value), do: Integer.to_string(value)
  def to_string_safe(_), do: "unknown"

  @doc """
  Extracts a tag value from metadata with a default fallback.

  ## Examples

      iex> extract_tag(%{status: "success"}, :status, "unknown")
      "success"

      iex> extract_tag(%{}, :status, "unknown")
      "unknown"
  """
  def extract_tag(metadata, key, default \\ "unknown") do
    metadata
    |> Map.get(key, default)
    |> to_string_safe()
  end

  @doc """
  Categorizes error messages to reduce metric cardinality.

  Groups similar errors into categories to prevent metric explosion
  while maintaining useful debugging information.

  ## Examples

      iex> categorize_error("email address from temporary/disposable email providers are not allowed")
      "disposable_email"

      iex> categorize_error("name: can't be blank")
      "validation_error"
  """
  def categorize_error(reason) when is_binary(reason) do
    cond do
      String.contains?(reason, "disposable") ->
        "disposable_email"

      String.contains?(reason, "rate limit") ->
        "rate_limited"

      String.contains?(reason, "email") and String.contains?(reason, "validation") ->
        "email_validation"

      String.contains?(reason, "can't be blank") ->
        "validation_error"

      String.contains?(reason, "has already been taken") ->
        "duplicate_error"

      true ->
        "other"
    end
  end

  def categorize_error(_), do: "unknown"
end
